#!/usr/bin/env python3

import argparse
import configparser
import logging
import os
import re
import subprocess

import boto3

AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")

IGNORED_ACCOUNT_KEYWORDS = ["finops"]

logger = logging.getLogger("awsorgsync")


def normalize(name):
    name = name.lower()
    return re.sub(r"[^a-z0-9-]", "-", name)


def ensure_sso_login(profile: str):
    subprocess.run(["aws", "sso", "login", "--profile", profile], check=True)


def load_config():
    config = configparser.RawConfigParser()
    config.read(AWS_CONFIG_PATH)
    return config


def extract_role_name(config, root_profile: str):
    section = f"profile {root_profile}"
    if not config.has_section(section):
        raise Exception(f"{root_profile} not found in AWS config")

    role_arn = config.get(section, "role_arn")
    return role_arn.split("/")[-1]


def extract_region(config, root_profile: str):
    section = f"profile {root_profile}"
    return config.get(section, "region")


def get_org_accounts(profile: str):
    session = boto3.Session(profile_name=profile)
    org = session.client("organizations")

    paginator = org.get_paginator("list_accounts")
    accounts = []

    for page in paginator.paginate():
        for acc in page["Accounts"]:
            if acc["Status"] == "ACTIVE":
                accounts.append(acc)

    return accounts


def populate_profiles(prefix: str, dry_run: bool = False):
    base_profile = prefix
    root_profile = f"{prefix}-root"

    logger.info("Logging in using %s...", base_profile)
    ensure_sso_login(base_profile)

    config = load_config()

    role_name = extract_role_name(config, root_profile)
    region = extract_region(config, root_profile)

    logger.info("Using role: %s", role_name)
    logger.info("Using region: %s", region)

    accounts = get_org_accounts(root_profile)
    skipped_accounts = []

    for account in accounts:
        account_name_raw = account["Name"]
        account_name_lower = account_name_raw.lower()

        if any(keyword in account_name_lower for keyword in IGNORED_ACCOUNT_KEYWORDS):
            skipped_accounts.append(account_name_raw)
            continue

        name = normalize(account_name_raw)
        account_id = account["Id"]

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
        logger.debug("  source_profile = %s", base_profile)
        logger.debug("  role_arn = arn:aws:iam::%s:role/%s", account_id, role_name)
        logger.debug("  region = %s", region)

        if not dry_run:
            config.add_section(new_profile)
            config.set(new_profile, "source_profile", base_profile)
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

    if not dry_run:
        with open(AWS_CONFIG_PATH, "w") as f:
            config.write(f)
        logger.info("Done.")
    else:
        logger.info("Dry run complete. No changes written.")


def list_profiles(prefix: str):
    config = load_config()
    pattern = re.compile(f"^profile {prefix}[-a-z0-9]*$")

    logger.info("Profiles with prefix '%s':", prefix)
    for section in config.sections():
        if pattern.match(section):
            profile_name = section.replace("profile ", "")
            logger.info("  - %s", profile_name)


def clean_profiles(prefix: str, dry_run: bool = False):
    config = load_config()
    pattern = re.compile(f"^profile {prefix}[-a-z0-9]*$")

    base_profile_section = f"profile {prefix}"
    root_profile_section = f"profile {prefix}-root"

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

    if not dry_run:
        with open(AWS_CONFIG_PATH, "w") as f:
            config.write(f)
        logger.info("Done.")
    else:
        logger.info("Dry run complete. No changes written.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (DEBUG level)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress non-error output"
    )
    parser.add_argument(
        "command", choices=["sync", "list", "clean"], help="Command to execute"
    )
    parser.add_argument(
        "prefix", help="Prefix for generated profile names (e.g. 'org')"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show changes without writing to config"
    )
    args = parser.parse_args()

    if args.verbose and args.quiet:
        parser.error("Cannot use --verbose and --quiet together")

    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level, format="%(message)s")

    if args.command == "sync":
        populate_profiles(args.prefix, dry_run=args.dry_run)
    elif args.command == "list":
        list_profiles(args.prefix)
    elif args.command == "clean":
        clean_profiles(args.prefix, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
