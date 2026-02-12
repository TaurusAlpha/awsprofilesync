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


def populate_profiles(prefix):
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

        config.add_section(new_profile)
        config.set(new_profile, "source_profile", base_profile)
        config.set(
            new_profile, "role_arn", f"arn:aws:iam::{account_id}:role/{role_name}"
        )
        config.set(new_profile, "region", region)

        print(f"Created profile: {prefix}-{name}")

    with open(AWS_CONFIG_PATH, "w") as f:
        config.write(f)

    print("Done.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["populate"])
    parser.add_argument("prefix")
    args = parser.parse_args()

    if args.command == "populate":
        populate_profiles(args.prefix)


if __name__ == "__main__":
    main()
