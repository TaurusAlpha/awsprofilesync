# awsprofilesync

A lightweight CLI utility for managing and synchronizing AWS CLI profiles across environments.

`awsprofilesync` allows you to automatically generate, reconcile, and clean AWS CLI profiles based on AWS Organizations or other future profile sources.

---

## Who Is This For?

`awsprofilesync` is designed for DevOps engineers, platform teams, and integrators managing multiple AWS accounts, customers, or environments.

It simplifies AWS CLI profile management in multi-account setups and reduces manual configuration overhead.

---

## Features

- Sync AWS CLI profiles from AWS Organizations
- Add missing profiles automatically
- Prune stale profiles
- Full clean of generated profiles (safe mode)
- Ignore specific accounts by keyword
- Account ID–based reconciliation (rename-safe)
- Dry-run support
- Structured logging with verbosity control

---

## Installation

This project is open-source and available under the MIT License.

### Option 1 – Clone the Repository

```bash
git clone git@github.com:TaurusAlpha/awsprofilesync.git
cd awsprofilesync
```

---

Run directly:

```bash
python main.py sync <prefix>
```

Or make executable and place in PATH:

```bash
chmod +x awsprofilesync
mv awsprofilesync /usr/local/bin/
```

---

## Usage

### Sync Profiles

```bash
awsprofilesync sync example
```

Creates missing profiles based on AWS Organization accounts.

### Sync with Prune (Reconcile)

```bash
awsprofilesync sync example --prune
```

Adds missing profiles and removes stale ones.

### Dry Run

```bash
awsprofilesync sync example --dry-run
```

Preview changes without modifying `~/.aws/config`.

### Clean All Generated Profiles

```bash
awsprofilesync clean example
```

Deletes all derived profiles for the prefix (base and root profiles are protected).

### List Profiles

```bash
awsprofilesync list example
```

---

## Naming Convention

Given prefix:

```
example
```

The tool expects:

```
[profile example]
[profile example-root]
```

Generated profiles:

```
[profile example-account-name]
```

If the AWS account name already contains the prefix, it will not be duplicated.

---

## Safety Guarantees

- Base SSO profile (`<prefix>`) is never deleted
- Root profile (`<prefix>-root`) is never deleted
- Reconciliation uses AWS Account IDs (not names)
- Dry-run mode available for all destructive operations

---

## Logging

| Flag | Behavior |
|------|----------|
| default | INFO level |
| `-v`, `--verbose` | DEBUG level |
| `-q`, `--quiet` | ERROR level |

Example:

```bash
awsprofilesync sync example -v
```

---

## Future Extensions

The architecture allows adding additional profile sources such as:

- CSV files
- Static configuration files
- Custom APIs

The tool focuses strictly on AWS CLI profile synchronization.

---

## License

MIT License.
