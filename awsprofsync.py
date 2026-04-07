#!/usr/bin/env python3
# Requires Python 3.10+

import argparse
import configparser
import os
import re
import subprocess
import sys

AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")
IGNORED_ACCOUNT_KEYWORDS = ["finops"]

# CLI verbosity flag (controlled by -v)
CLI_VERBOSE = False

# ANSI Color Codes
COLORS = {
    "green": "\033[32m",
    "bright_green": "\033[92m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}


def cli_print(msg: str, *args, style: str | None = None, err: bool = False) -> None:
    """Pretty prints to terminal using ANSI codes."""
    text = msg % args if args else msg
    color = COLORS.get(style or "", "")
    reset = COLORS["reset"] if color else ""

    output = f"{color}{text}{reset}"
    if err:
        print(output, file=sys.stderr)
    else:
        print(output)


# Logic for AWS interaction (boto3 still required for Org access)
try:
    import boto3
except ImportError:
    cli_print(
        "ERROR: 'boto3' library is required. Install via 'pip install boto3'",
        style="red",
        err=True,
    )
    sys.exit(1)


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


def _prompt_yes_no(prompt: str, default: bool = False) -> bool:
    default_str = "Y/n" if default else "y/N"
    resp = input(f"{prompt} ({default_str}): ").strip().lower()
    if not resp:
        return default
    return resp[0] == "y"


def init_profiles(prefix: str, dry_run: bool = False) -> None:
    cli_print("Initializing profiles for prefix: %s", prefix, style="green")
    config = load_config()

    defaults_section = "dummy"
    defaults: dict[str, str] = {}
    if config.has_section(defaults_section):
        try:
            for k, v in config.items(defaults_section):
                defaults[k] = v
        except Exception:
            pass

    profile_dummy = f"profile {defaults_section}"
    if config.has_section(profile_dummy):
        try:
            role_arn_val = config.get(profile_dummy, "role_arn", fallback=None)
            if role_arn_val:
                acct = extract_account_id_from_arn(role_arn_val)
                if acct:
                    defaults.setdefault("sso_account_id", acct)
                defaults.setdefault("role_arn", role_arn_val)
                defaults.setdefault("role_name", role_arn_val.split("/")[-1])
            defaults.setdefault(
                "region", config.get(profile_dummy, "region", fallback="")
            )
        except Exception:
            pass

    def _ask(
        key: str, prompt_text: str, fallback: str = "", required: bool = False
    ) -> str:
        d = defaults.get(key, fallback)
        if d:
            resp = input(f"{prompt_text} [{d}]: ").strip()
            return resp if resp else d
        else:
            while True:
                resp = input(f"{prompt_text}: ").strip()
                if resp:
                    return resp
                if not required:
                    return ""

    sso_start_url = _ask("sso_start_url", "SSO Start URL")
    sso_region = _ask("sso_region", "SSO region", required=True)
    sso_account_id = _ask("sso_account_id", "SSO account id", required=True)
    customer_name = _ask("customer_name", "Customer/account name", required=True)
    role_name = _ask(
        "role_name", "Role name to assume", defaults.get("role_name", ""), required=True
    )
    region = _ask("region", "Default region", sso_region) or sso_region

    base_section = f"profile {prefix}"
    root_section = f"profile {prefix}-root"

    cli_print("\nPlanned profile sections:", style="bold")
    cli_print(" - %s (SSO profile)", base_section, style="cyan")
    cli_print(" - %s (root role_arn + region)", root_section, style="cyan")

    cli_print("\nSummary of values:", style="bold")
    cli_print("  SSO Account:   %s", sso_account_id, style="cyan")
    cli_print("  Role Name:     %s", role_name, style="cyan")
    cli_print("  Region:        %s", region, style="cyan")

    if not _prompt_yes_no("\nProceed?", default=True):
        cli_print("Aborted.", style="yellow")
        return

    if config.has_section(base_section):
        if not _prompt_yes_no(
            f"Section {base_section} exists. Overwrite?", default=False
        ):
            cli_print(f"Skipping {base_section}", style="yellow")
        else:
            config.remove_section(base_section)

    if not dry_run:
        if not config.has_section(base_section):
            config.add_section(base_section)
        if sso_start_url:
            config.set(base_section, "sso_start_url", sso_start_url)
        if sso_region:
            config.set(base_section, "sso_region", sso_region)

        for dk, dv in defaults.items():
            if dv and (
                dk.startswith("sso_") or dk in ("output", "retry_mode", "cli_pager")
            ):
                try:
                    config.set(base_section, dk, dv)
                except Exception:
                    pass

        config.set(base_section, "sso_account_id", sso_account_id)
        config.set(base_section, "sso_role_name", role_name)

    role_arn = (
        defaults.get("role_arn") or f"arn:aws:iam::{sso_account_id}:role/{role_name}"
    )
    if config.has_section(root_section):
        if not _prompt_yes_no(
            f"Section {root_section} exists. Overwrite?", default=False
        ):
            cli_print(f"Skipping {root_section}", style="yellow")
        else:
            config.remove_section(root_section)

    if not dry_run:
        if not config.has_section(root_section):
            config.add_section(root_section)
        config.set(root_section, "role_arn", role_arn)
        if region:
            config.set(root_section, "region", region)

    finalize_write(config, dry_run, "Init complete.")


def handle_init(args) -> int:
    init_profiles(args.prefix, dry_run=args.dry_run)
    return 0


def normalize(name: str) -> str:
    result = re.sub(r"[^a-z0-9-]", "-", name.lower())
    result = re.sub(r"-+", "-", result)
    return result.strip("-")


def ensure_sso_login(profile: str):
    try:
        subprocess.run(
            ["aws", "sts", "get-caller-identity", "--profile", profile],
            check=True,
            capture_output=True,
        )
        cli_print(
            "Existing session for profile '%s' is active.", profile, style="green"
        )
    except subprocess.CalledProcessError:
        try:
            cli_print(
                "Session expired or missing. Logging in using %s...",
                profile,
                style="yellow",
            )
            subprocess.run(["aws", "sso", "login", "--profile", profile], check=True)
        except subprocess.CalledProcessError as e:
            cli_print(
                "SSO login failed for profile %s: %s", profile, e, style="red", err=True
            )
            raise


def load_config():
    config = configparser.RawConfigParser()
    config.read(AWS_CONFIG_PATH)
    return config


def write_config(config):
    with open(AWS_CONFIG_PATH, "w") as f:
        config.write(f)


def finalize_write(config, dry_run: bool, success_message: str):
    if not dry_run:
        write_config(config)
        cli_print(success_message, style="green")
    else:
        cli_print("Dry run complete. No changes written.", style="yellow")


def get_prefix_pattern(prefix: str):
    return re.compile(f"^profile {prefix}[-a-z0-9]*$")


def get_protected_sections(prefix: str):
    return (f"profile {prefix}", f"profile {prefix}-root")


def extract_role_name(config, root_profile: str):
    section = f"profile {root_profile}"
    if not config.has_section(section):
        raise Exception(f"{root_profile} not found in AWS config")
    role_arn = config.get(section, "role_arn")
    if not role_arn or ":iam::" not in role_arn:
        raise ValueError(f"Invalid role_arn in {section}")
    return role_arn.split("/")[-1]


def extract_region(config, root_profile: str):
    return config.get(f"profile {root_profile}", "region")


def extract_account_id_from_arn(role_arn: str) -> str | None:
    if not role_arn or ":iam::" not in role_arn:
        return None
    parts = role_arn.split(":")
    return parts[4] if len(parts) >= 5 else None


def get_org_accounts(profile: str):
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
        cli_print(
            "Failed to retrieve AWS Organization accounts: %s", e, style="red", err=True
        )
        raise


def populate_profiles(prefix: str, dry_run: bool = False) -> list[str]:
    sso_profile, root_profile = prefix, f"{prefix}-root"
    config = load_config()

    if config.has_section(f"profile {sso_profile}"):
        ensure_sso_login(sso_profile)
    else:
        ensure_sso_login("default")

    role_name = extract_role_name(config, root_profile)
    region = extract_region(config, root_profile)

    cli_print("Using role: %s", role_name, style="cyan")
    cli_print("Using region: %s", region, style="cyan")

    accounts = get_org_accounts(root_profile)
    active_account_ids = []

    existing_account_ids = set()
    pattern = get_prefix_pattern(prefix)
    for section in config.sections():
        if pattern.match(section):
            try:
                acc_id = extract_account_id_from_arn(config.get(section, "role_arn"))
                if acc_id:
                    existing_account_ids.add(acc_id)
            except Exception:
                pass

    for account in accounts:
        if any(kw in account["Name"].lower() for kw in IGNORED_ACCOUNT_KEYWORDS):
            continue

        name, account_id = normalize(account["Name"]), account["Id"]
        active_account_ids.append(account_id)

        if account_id in existing_account_ids:
            if CLI_VERBOSE:
                cli_print(
                    "Skipping %s (%s) - already exists",
                    account["Name"],
                    account_id,
                    style="yellow",
                )
            continue

        final_name = name if name.startswith(f"{prefix}-") else f"{prefix}-{name}"
        new_section = f"profile {final_name}"

        if config.has_section(new_section):
            continue

        if dry_run:
            cli_print("[DRY-RUN] Create profile: %s", final_name, style="yellow")
        else:
            cli_print("Creating profile: %s", final_name, style="green")
            config.add_section(new_section)
            config.set(new_section, "source_profile", sso_profile)
            config.set(
                new_section, "role_arn", f"arn:aws:iam::{account_id}:role/{role_name}"
            )
            config.set(new_section, "region", region)

    finalize_write(config, dry_run, "Done.")
    return active_account_ids


def prune_stale_profiles(
    prefix: str, active_accounts: list[str], dry_run: bool = False
):
    config = load_config()
    pattern = get_prefix_pattern(prefix)
    protected = get_protected_sections(prefix)
    expected = set(active_accounts)

    to_delete = []
    for section in config.sections():
        if not pattern.match(section) or section in protected:
            continue
        try:
            acc_id = extract_account_id_from_arn(config.get(section, "role_arn"))
            if acc_id not in expected:
                to_delete.append(section)
        except Exception:
            continue

    if not to_delete:
        cli_print("No stale profiles found.", style="green")
        return

    for section in to_delete:
        name = section.replace("profile ", "")
        if dry_run:
            cli_print("[DRY-RUN] Prune profile: %s", name, style="yellow")
        else:
            cli_print("Pruning profile: %s", name, style="red")
            config.remove_section(section)

    finalize_write(config, dry_run, "Prune complete.")


def list_profiles(prefix: str):
    config = load_config()
    pattern = get_prefix_pattern(prefix)
    cli_print("Profiles for '%s':", prefix, style="bold")
    for section in config.sections():
        if pattern.match(section):
            name = section.replace("profile ", "")
            cli_print("  - %s", name, style="bright_green")
            if CLI_VERBOSE:
                role = config.get(section, "role_arn", fallback="N/A").split("/")[-1]
                cli_print("    Role: %s", role, style="cyan")


def clean_profiles(prefix: str, dry_run: bool = False):
    config = load_config()
    pattern = get_prefix_pattern(prefix)
    protected = get_protected_sections(prefix)
    to_delete = [
        s for s in config.sections() if pattern.match(s) and s not in protected
    ]

    for section in to_delete:
        name = section.replace("profile ", "")
        if dry_run:
            cli_print("[DRY-RUN] Delete profile: %s", name, style="yellow")
        else:
            cli_print("Cleaning profile: %s", name, style="red")
            config.remove_section(section)
    finalize_write(config, dry_run, "Clean complete.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("-v", "--verbose", action="store_true")
    parent.add_argument("-q", "--quiet", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    for cmd in ["sync", "list", "clean", "init"]:
        sp = sub.add_parser(cmd, parents=[parent])
        sp.add_argument("prefix")
        if cmd in ["sync", "clean", "init"]:
            sp.add_argument("--dry-run", action="store_true")
        if cmd == "sync":
            sp.add_argument("-p", "--prune", action="store_true")
        sp.set_defaults(func=globals()[f"handle_{cmd}"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    global CLI_VERBOSE
    CLI_VERBOSE = bool(args.verbose) and not bool(args.quiet)
    try:
        return int(args.func(args))
    except Exception as e:
        cli_print("Failed: %s", e, style="red", err=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
