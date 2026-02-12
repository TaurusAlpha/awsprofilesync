#!/usr/bin/env python3

import argparse
import configparser
import os
import re
import subprocess

import boto3

AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")


def normalize(name):
    name = name.lower()
    return re.sub(r"[^a-z0-9-]", "-", name)


def ensure_sso_login(profile):
    subprocess.run(["aws", "sso", "login", "--profile", profile], check=True)


def load_config():
    config = configparser.RawConfigParser()
    config.read(AWS_CONFIG_PATH)
    return config


def extract_role_name(config, root_profile):
    section = f"profile {root_profile}"
    if not config.has_section(section):
        raise Exception(f"{root_profile} not found in AWS config")

    role_arn = config.get(section, "role_arn")
    return role_arn.split("/")[-1]


def extract_region(config, root_profile):
    section = f"profile {root_profile}"
    return config.get(section, "region")


def get_org_accounts(profile):
    session = boto3.Session(profile_name=profile)
    org = session.client("organizations")

    paginator = org.get_paginator("list_accounts")
    accounts = []

    for page in paginator.paginate():
        for acc in page["Accounts"]:
            if acc["Status"] == "ACTIVE":
                accounts.append(acc)

    return accounts


def populate_profiles(prefix, dry_run=False):
    base_profile = prefix
    root_profile = f"{prefix}-root"

    print(f"Logging in using {base_profile}...")
    ensure_sso_login(base_profile)

    config = load_config()

    role_name = extract_role_name(config, root_profile)
    region = extract_region(config, root_profile)

    print(f"Using role: {role_name}")
    print(f"Using region: {region}")

    accounts = get_org_accounts(root_profile)

    for account in accounts:
        name = normalize(account["Name"])
        account_id = account["Id"]
        new_profile = f"profile {prefix}-{name}"

        if config.has_section(new_profile):
            continue

        print(f"{'[DRY-RUN] ' if dry_run else ''}Would create profile: {prefix}-{name}")
        print(f"  source_profile = {base_profile}")
        print(f"  role_arn = arn:aws:iam::{account_id}:role/{role_name}")
        print(f"  region = {region}")

        if not dry_run:
            config.add_section(new_profile)
            config.set(new_profile, "source_profile", base_profile)
            config.set(
                new_profile,
                "role_arn",
                f"arn:aws:iam::{account_id}:role/{role_name}",
            )
            config.set(new_profile, "region", region)

    if not dry_run:
        with open(AWS_CONFIG_PATH, "w") as f:
            config.write(f)
        print("Done.")
    else:
        print("Dry run complete. No changes written.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["sync"])
    parser.add_argument("prefix")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show changes without writing to config"
    )
    args = parser.parse_args()

    if args.command == "sync":
        populate_profiles(args.prefix, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
