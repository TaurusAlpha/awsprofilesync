#!/usr/bin/env python3
# Requires Python 3.10+

import argparse
import configparser
import logging
import os
import re
import subprocess
import sys

import boto3

AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")

IGNORED_ACCOUNT_KEYWORDS = ["finops"]

logger = logging.getLogger("awsprofilesync")


def handle_sync(args) -> int:
    active_accounts = populate_profiles(args.prefix, dry_run=args.dry_run)
    if args.prune:
        prune_stale_profiles(args.prefix, active_accounts, dry_run=args.dry_run)
    return 0


def handle_list(args) -> int:
    list_profiles(args.prefix)
    return 0


def handle_clean(args) -> int:
    clean_profiles(args.prefix, dry_run=args.dry_run)
    return 0


def normalize(name: str) -> str:
    """
    Normalize AWS account name to a safe profile suffix.
    - Lowercase
    - Replace invalid characters with '-'
    - Collapse consecutive dashes
    - Remove leading/trailing dashes
    """
    result = re.sub(r"[^a-z0-9-]", "-", name.lower())
    result = re.sub(r"-+", "-", result)
    return result.strip("-")


def ensure_sso_login(profile: str):
    """
    Ensure AWS SSO session is active for the given profile.
    """
    try:
        logger.info("Logging in using %s...", profile)
        subprocess.run(
            ["aws", "sso", "login", "--profile", profile],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error("SSO login failed for profile %s: %s", profile, e)
        raise


def load_config():
    """
    Load AWS CLI configuration file.
    """
    config = configparser.RawConfigParser()
    config.read(AWS_CONFIG_PATH)
    return config


def write_config(config):
    """
    Persist AWS CLI configuration to disk.
    """
    with open(AWS_CONFIG_PATH, "w") as f:
        config.write(f)


def finalize_write(config, dry_run: bool, success_message: str):
    """
    Write configuration unless dry-run, and log appropriate message.
    """
    if not dry_run:
        write_config(config)
        logger.info(success_message)
    else:
        logger.info("Dry run complete. No changes written.")


def get_prefix_pattern(prefix: str):
    """
    Compile regex pattern to match profile sections with given prefix.
    """
    return re.compile(f"^profile {prefix}[-a-z0-9]*$")


def get_protected_sections(prefix: str):
    """
    Return tuple of protected profile section names for base and root profiles.
    """
    return (
        f"profile {prefix}",
        f"profile {prefix}-root",
    )


def extract_role_name(config, root_profile: str):
    """
    Extract role name from role_arn in root profile section.
    Raises if role_arn is invalid or missing.
    """
    section = f"profile {root_profile}"
    if not config.has_section(section):
        raise Exception(f"{root_profile} not found in AWS config")

    role_arn = config.get(section, "role_arn")
    if not role_arn or ":iam::" not in role_arn:
        raise ValueError(f"Invalid role_arn in {section}")
    return role_arn.split("/")[-1]


def extract_region(config, root_profile: str):
    """
    Extract region from root profile section.
    """
    section = f"profile {root_profile}"
    return config.get(section, "region")


def extract_account_id_from_arn(role_arn: str) -> str | None:
    """
    Extract AWS account ID from role ARN.
    Returns None if ARN format is invalid.
    """
    if not role_arn or ":iam::" not in role_arn:
        return None

    parts = role_arn.split(":")
    if len(parts) < 5:
        return None

    return parts[4]


def get_org_accounts(profile: str):
    """
    Retrieve all ACTIVE AWS Organization accounts using given profile.
    """
    try:
        session = boto3.Session(profile_name=profile)
        org = session.client("organizations")
        paginator = org.get_paginator("list_accounts")

        accounts = []
        for page in paginator.paginate():
            for acc in page["Accounts"]:
                if acc["Status"] == "ACTIVE":
                    accounts.append(acc)
        return accounts
    except Exception as e:
        logger.error("Failed to retrieve AWS Organization accounts: %s", e)
        raise


def populate_profiles(
    prefix: str,
    dry_run: bool = False,
) -> list[str]:
    """
    Create missing AWS CLI profiles for the given prefix.
    Returns list of active account IDs.
    """
    sso_profile = prefix
    root_profile = f"{prefix}-root"

    config = load_config()
    base_profile_section = f"profile {sso_profile}"
    if config.has_section(base_profile_section):
        ensure_sso_login(sso_profile)
    else:
        logger.debug(
            "Base profile '%s' not found in config, falling back to 'default'",
            sso_profile,
        )
        ensure_sso_login("default")

    role_name = extract_role_name(config, root_profile)
    region = extract_region(config, root_profile)

    logger.info("Using role: %s", role_name)
    logger.info("Using region: %s", region)

    accounts = get_org_accounts(root_profile)
    skipped_accounts = []
    active_account_ids = []

    # Collect existing account IDs from current config only within prefix scope
    existing_account_ids = set()
    prefix_pattern = get_prefix_pattern(prefix)
    for section in config.sections():
        if not prefix_pattern.match(section):
            continue
        try:
            role_arn = config.get(section, "role_arn")
            account_id = extract_account_id_from_arn(role_arn)
            if account_id:
                existing_account_ids.add(account_id)
        except Exception:
            continue

    for account in accounts:
        account_name_raw = account["Name"]

        if any(
            keyword in account_name_raw.lower() for keyword in IGNORED_ACCOUNT_KEYWORDS
        ):
            skipped_accounts.append(account_name_raw)
            continue

        name = normalize(account_name_raw)
        account_id = account["Id"]
        active_account_ids.append(account_id)

        if account_id in existing_account_ids:
            logger.info(
                "Skipping account %s (%s) - profile with same account ID already exists",
                account_name_raw,
                account_id,
            )
            continue

        # Avoid double prefix
        if name.startswith(f"{prefix}-"):
            final_profile_name = name
        else:
            final_profile_name = f"{prefix}-{name}"

        new_profile = f"profile {final_profile_name}"

        if config.has_section(new_profile):
            continue

        if dry_run:
            logger.info("[DRY-RUN] Would create profile: %s", final_profile_name)
        else:
            logger.info("Creating profile: %s", final_profile_name)
        logger.debug("  source_profile = %s", sso_profile)
        logger.debug("  role_arn = arn:aws:iam::%s:role/%s", account_id, role_name)
        logger.debug("  region = %s", region)

        if not dry_run:
            config.add_section(new_profile)
            config.set(new_profile, "source_profile", sso_profile)
            config.set(
                new_profile,
                "role_arn",
                f"arn:aws:iam::{account_id}:role/{role_name}",
            )
            config.set(new_profile, "region", region)

    if skipped_accounts:
        logger.info("Skipped accounts:")
        for acc in skipped_accounts:
            logger.info("  - %s", acc)

    finalize_write(config, dry_run, "Done.")

    return active_account_ids


def prune_stale_profiles(
    prefix: str, active_accounts: list[str], dry_run: bool = False
):
    """
    Remove profiles under prefix whose account IDs are no longer active.
    """
    config = load_config()
    pattern = get_prefix_pattern(prefix)

    base_profile_section, root_profile_section = get_protected_sections(prefix)

    # Build expected account IDs set
    expected_account_ids = set(active_accounts)

    profiles_to_delete = []
    for section in config.sections():
        if not pattern.match(section):
            continue
        if section in (base_profile_section, root_profile_section):
            continue

        # Extract account ID from role_arn
        try:
            role_arn = config.get(section, "role_arn")
            account_id = extract_account_id_from_arn(role_arn)
            if not account_id:
                logger.debug("Invalid role_arn format in %s", section)
                continue
        except Exception:
            logger.debug("Skipping profile without valid role_arn: %s", section)
            continue

        if account_id not in expected_account_ids:
            profiles_to_delete.append(section)

    if not profiles_to_delete:
        logger.info("No stale profiles found for prefix '%s'", prefix)
        return

    for profile in profiles_to_delete:
        profile_name = profile.replace("profile ", "")
        if dry_run:
            logger.info("[DRY-RUN] Would prune profile: %s", profile_name)
        else:
            logger.info("Pruning profile: %s", profile_name)
            config.remove_section(profile)

    finalize_write(config, dry_run, "Prune complete.")


def list_profiles(prefix: str):
    """
    List all profiles matching prefix.
    """
    config = load_config()
    pattern = get_prefix_pattern(prefix)

    logger.info("Profiles with prefix '%s':", prefix)
    for section in config.sections():
        if pattern.match(section):
            profile_name = section.replace("profile ", "")
            logger.info("  - %s", profile_name)
            logger.debug(
                "   account_id = %s",
                extract_account_id_from_arn(
                    config.get(section, "role_arn", fallback="None")
                ),
            )
            logger.debug(
                "   role = %s",
                config.get(section, "role_arn", fallback="None").split("/")[-1],
            )
            logger.debug(
                "   region = %s", config.get(section, "region", fallback="N/A")
            )


def clean_profiles(prefix: str, dry_run: bool = False):
    """
    Remove all derived profiles for prefix (excluding base/root).
    """
    config = load_config()
    pattern = get_prefix_pattern(prefix)

    base_profile_section, root_profile_section = get_protected_sections(prefix)

    profiles_to_delete = [
        s
        for s in config.sections()
        if pattern.match(s) and s not in (base_profile_section, root_profile_section)
    ]

    logger.debug(
        "Protected profiles: %s, %s",
        base_profile_section.replace("profile ", ""),
        root_profile_section.replace("profile ", ""),
    )

    if not profiles_to_delete:
        logger.info("No profiles found with prefix '%s'", prefix)
        return

    for profile in profiles_to_delete:
        profile_name = profile.replace("profile ", "")
        if dry_run:
            logger.info("[DRY-RUN] Would clean profile: %s", profile_name)
        else:
            logger.info("Cleaning profile: %s", profile_name)
            config.remove_section(profile)

    finalize_write(config, dry_run, "Done.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (DEBUG level)",
    )
    parent_parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress non-error output"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- sync command ---
    sync_parser = subparsers.add_parser(
        "sync", help="Sync profiles from AWS Organization", parents=[parent_parser]
    )
    sync_parser.add_argument(
        "prefix", help="Prefix for generated profile names (e.g. 'org')"
    )
    sync_parser.add_argument(
        "--dry-run", action="store_true", help="Show changes without writing to config"
    )
    sync_parser.add_argument(
        "-p",
        "--prune",
        action="store_true",
        help="Remove profiles not present in AWS Org",
    )
    sync_parser.set_defaults(func=handle_sync)

    # --- list command ---
    list_parser = subparsers.add_parser(
        "list", help="List profiles with prefix", parents=[parent_parser]
    )
    list_parser.add_argument(
        "prefix", help="Prefix for generated profile names (e.g. 'org')"
    )
    list_parser.set_defaults(func=handle_list)

    # --- clean command ---
    clean_parser = subparsers.add_parser(
        "clean", help="Delete profiles with prefix", parents=[parent_parser]
    )
    clean_parser.add_argument(
        "prefix", help="Prefix for generated profile names (e.g. 'org')"
    )
    clean_parser.add_argument(
        "--dry-run", action="store_true", help="Show changes without writing to config"
    )
    clean_parser.set_defaults(func=handle_clean)

    return parser


def configure_logging(verbose: bool, quiet: bool) -> None:
    """
    Configure logging level and handler based on CLI flags.
    verbose -> DEBUG
    quiet   -> ERROR
    default -> INFO
    """
    if verbose and quiet:
        print("ERROR: Cannot use --verbose and --quiet together.", file=sys.stderr)
        sys.exit(2)

    # Determine level
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    logger.setLevel(level)

    # Avoid duplicate handlers if configure_logging() is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose, quiet=args.quiet)

    logger.debug("Arguments parsed successfully.")
    logger.debug(f"Command: {args.command}")

    try:
        return int(args.func(args))
    except Exception as e:
        logger.error("Failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
