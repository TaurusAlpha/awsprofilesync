#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import datetime as _dt
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SWITCH_ROLE_URL = "https://signin.aws.amazon.com/switchrole"
ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role\/(.+)$")

logger = logging.getLogger("awsurlsync")


@dataclass(frozen=True)
class ProfileBookmark:
    aws_profile: str
    name: str
    account_id: str
    role_name: str

    @property
    def url(self) -> str:
        # Keep displayName as the full aws profile name to reduce confusion.
        # URL encode is not strictly required for common values but we do minimal safety.
        from urllib.parse import quote

        return (
            f"{SWITCH_ROLE_URL}"
            f"?roleName={quote(self.role_name)}"
            f"&account={quote(self.account_id)}"
            f"&displayName={quote(self.aws_profile)}"
        )


def is_macos() -> bool:
    return sys.platform == "darwin"


def chrome_running() -> bool:
    """Detect whether Google Chrome is running (best-effort)."""
    try:
        # -x exact match
        r = subprocess.run(
            ["pgrep", "-x", "Google Chrome"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        # If pgrep is unavailable or blocked, do not fail the tool.
        return False


def aws_config_path() -> Path:
    return Path(os.path.expanduser("~/.aws/config"))


def format_display_name(name: str) -> str:
    """
    Remove dashes/underscores and capitalize each word.
    Examples:
      root -> Root
      audit-log -> Audit Log
      example_stage_env -> Example Stage Env
    """
    cleaned = name.replace("-", " ").replace("_", " ")
    parts = [p for p in cleaned.split() if p]
    return " ".join(p.capitalize() for p in parts)


def read_aws_profiles(prefix: str, config_file: Path) -> List[ProfileBookmark]:
    """Parse ~/.aws/config and return bookmarks for profiles matching prefix-*.

    Only profiles in config (not credentials) are used.
    """
    cp = configparser.RawConfigParser()
    cp.read(config_file)

    logger.debug(f"Loaded AWS config from {config_file}")

    wanted_prefix = f"profile {prefix}-"

    bookmarks: List[ProfileBookmark] = []
    skipped: List[str] = []

    for section in cp.sections():
        # AWS config uses sections like: [profile name]
        if not section.startswith(wanted_prefix):
            continue

        logger.debug(f"Matched profile section: {section}")

        aws_profile = section[len("profile ") :].strip()
        # Remove prefix- from name for bookmark display
        name = aws_profile
        if name.startswith(f"{prefix}-"):
            name = name[len(prefix) + 1 :]

        name = format_display_name(name)

        role_arn = cp.get(section, "role_arn", fallback="").strip()
        if not role_arn:
            skipped.append(f"{aws_profile} (missing role_arn)")
            continue

        m = ROLE_ARN_RE.match(role_arn)
        if not m:
            skipped.append(f"{aws_profile} (invalid role_arn: {role_arn})")
            continue

        account_id, role_name = m.group(1), m.group(2)
        bookmarks.append(
            ProfileBookmark(
                aws_profile=aws_profile,
                name=name,
                account_id=account_id,
                role_name=role_name,
            )
        )

    # Warn on skips
    for s in skipped:
        logger.warning(f"skipping profile: {s}")

    # Warn on duplicate bookmark names (within this prefix run) and skip duplicates
    seen_names: set[str] = set()
    deduped: List[ProfileBookmark] = []
    for b in bookmarks:
        if b.name in seen_names:
            logger.warning(
                f"duplicate bookmark name '{b.name}' derived from profile '{b.aws_profile}'. Skipping."
            )
            continue
        seen_names.add(b.name)
        deduped.append(b)

    return deduped


def chrome_bookmarks_file(chrome_profile: str) -> Path:
    """Return path to Chrome bookmarks file on macOS for a given profile name."""
    base = Path(os.path.expanduser("~/Library/Application Support/Google/Chrome"))
    return base / chrome_profile / "Bookmarks"


def load_bookmarks_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def make_backup(path: Path) -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
    backup = path.with_name(path.name + f".bak-{ts}")
    shutil.copy2(path, backup)
    return backup


def iter_nodes(node: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Yield all nodes in a bookmark subtree."""
    yield node
    children = node.get("children")
    if isinstance(children, list):
        for c in children:
            if isinstance(c, dict):
                yield from iter_nodes(c)


def max_bookmark_id(bookmarks: Dict[str, Any]) -> int:
    """Return the maximum numeric id in the bookmarks file."""
    roots = bookmarks.get("roots", {})
    max_id = 0
    if isinstance(roots, dict):
        for root in roots.values():
            if isinstance(root, dict):
                for n in iter_nodes(root):
                    i = n.get("id")
                    if isinstance(i, str) and i.isdigit():
                        max_id = max(max_id, int(i))
    return max_id


def now_chrome_timestamp() -> str:
    """Chrome stores dates as microseconds since 1601-01-01 UTC (Windows epoch)."""
    # This is best-effort; Chrome will tolerate missing date fields in many cases,
    # but we populate them for cleanliness.
    epoch_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    micros = int((now - epoch_1601).total_seconds() * 1_000_000)
    return str(micros)


def find_or_create_folder(
    parent: Dict[str, Any],
    folder_name: str,
    next_id: List[int],
) -> Dict[str, Any]:
    """Find a folder by name under parent; create if missing."""
    children = parent.setdefault("children", [])
    if not isinstance(children, list):
        raise ValueError("Invalid bookmarks structure: children is not a list")

    for c in children:
        if (
            isinstance(c, dict)
            and c.get("type") == "folder"
            and c.get("name") == folder_name
        ):
            return c

    next_id[0] += 1
    folder = {
        "type": "folder",
        "name": folder_name,
        "id": str(next_id[0]),
        "date_added": now_chrome_timestamp(),
        "date_modified": now_chrome_timestamp(),
        "children": [],
    }
    children.append(folder)
    return folder


def folder_has_bookmark(folder: Dict[str, Any], name: str, url: str) -> bool:
    children = folder.get("children", [])
    if not isinstance(children, list):
        return False
    for c in children:
        if not isinstance(c, dict):
            continue
        if c.get("type") == "url":
            if c.get("name") == name:
                return True
            # Also treat same URL as duplicate to avoid multiple identical entries.
            if c.get("url") == url:
                return True
    return False


def add_bookmark(
    folder: Dict[str, Any],
    name: str,
    url: str,
    next_id: List[int],
) -> bool:
    """Add bookmark to folder. Returns True if added, False if skipped."""
    if folder_has_bookmark(folder, name=name, url=url):
        return False

    children = folder.setdefault("children", [])
    if not isinstance(children, list):
        raise ValueError("Invalid bookmarks structure: children is not a list")

    next_id[0] += 1
    node = {
        "type": "url",
        "name": name,
        "url": url,
        "id": str(next_id[0]),
        "date_added": now_chrome_timestamp(),
    }
    children.append(node)
    return True


def ensure_path_and_sync(
    bookmarks_json: Dict[str, Any],
    prefix: str,
    items: List[ProfileBookmark],
    path_spec: Optional[str] = None,
) -> Tuple[int, int]:
    """Ensure folder path and add bookmarks. Returns (added, skipped)."""
    roots = bookmarks_json.get("roots")
    if not isinstance(roots, dict):
        raise ValueError("Invalid bookmarks JSON: missing roots")

    # Always use Bookmarks Bar as root
    current = roots.get("bookmark_bar")
    if not isinstance(current, dict):
        raise ValueError("Invalid bookmarks JSON: missing roots.bookmark_bar")

    # Build folder structure:
    # <extra path (if any)> / <FIRST_LETTER> / <CapitalizedPrefix>

    first_letter = prefix[:1].upper() if prefix else "_"
    prefix_clean = format_display_name(prefix)

    folder_parts = []

    if path_spec:
        extra_parts = [p.strip() for p in path_spec.split("/") if p.strip()]
        if not extra_parts:
            raise ValueError("Invalid path_spec")
        folder_parts.extend(extra_parts)

    folder_parts.extend([first_letter, prefix_clean])

    logger.debug(f"Resolved folder structure: {folder_parts}")

    next_id = [max_bookmark_id(bookmarks_json)]

    # Create/resolve folder chain
    for part in folder_parts:
        current = find_or_create_folder(current, part, next_id)

    target_folder = current

    added = 0
    skipped = 0

    for b in items:
        ok = add_bookmark(target_folder, b.name, b.url, next_id)
        if ok:
            added += 1
        else:
            skipped += 1
            logger.warning(
                f"bookmark exists (name or url duplicate), skipping: {b.name} -> {b.url}"
            )

    # Update date_modified for folder touched
    target_folder["date_modified"] = now_chrome_timestamp()

    return added, skipped


def cmd_sync(args: argparse.Namespace) -> int:
    if not is_macos():
        logger.error("This version supports macOS only.")
        return 2

    config_file = Path(args.aws_config).expanduser()
    if not config_file.exists():
        logger.error(f"AWS config not found: {config_file}")
        return 2

    if chrome_running():
        logger.warning(
            "Google Chrome appears to be running. Chrome may overwrite bookmarks on exit. Consider closing Chrome before syncing."
        )

    chrome_profile = args.chrome_profile
    bm_file = chrome_bookmarks_file(chrome_profile)
    if not bm_file.exists():
        logger.error(f"Chrome bookmarks file not found: {bm_file}")
        logger.error(
            "Hint: check --chrome-profile (e.g., 'Default', 'Profile 1', etc.)"
        )
        return 2

    items = read_aws_profiles(prefix=args.prefix, config_file=config_file)
    if not items:
        logger.info(f"No profiles found matching '{args.prefix}-*' in {config_file}")
        return 0

    # Additional warning: same (account_id, role_name) multiple times
    seen_roles: set[Tuple[str, str]] = set()
    for b in items:
        key = (b.account_id, b.role_name)
        if key in seen_roles:
            logger.warning(
                f"multiple profiles map to same account+role ({b.account_id}, {b.role_name}). "
                f"This run will still proceed, but consider cleanup: latest seen profile '{b.aws_profile}'."
            )
        seen_roles.add(key)

    if args.dry_run:
        logger.info(
            f"DRY-RUN: would sync {len(items)} bookmarks to Chrome profile '{chrome_profile}'"
        )
        prefix_clean = format_display_name(args.prefix)
        first_letter = args.prefix[:1].upper() if args.prefix else "_"

        if getattr(args, "path", None):
            logger.info(
                f"Target path: Bookmarks bar/{args.path}/{first_letter}/{prefix_clean}"
            )
        else:
            logger.info(f"Target path: Bookmarks bar/{first_letter}/{prefix_clean}")
        for b in items:
            logger.info(f"  - {b.name} -> {b.url}")
        return 0

    # Read-modify-write with backup
    try:
        data = load_bookmarks_json(bm_file)
        logger.debug("Bookmarks JSON loaded successfully.")
    except Exception as ex:
        logger.error(f"failed to read bookmarks JSON: {bm_file}: {ex}")
        return 2

    try:
        logger.debug(f"Creating backup of bookmarks file: {bm_file}")
        backup = make_backup(bm_file)
    except Exception as ex:
        logger.error(f"failed to create backup for {bm_file}: {ex}")
        return 2

    try:
        added, skipped = ensure_path_and_sync(
            data,
            args.prefix,
            items,
            path_spec=getattr(args, "path", None),
        )
    except Exception as ex:
        logger.error(f"failed to update bookmarks structure: {ex}")
        logger.error(f"Backup remains at: {backup}")
        return 2

    try:
        atomic_write_json(bm_file, data)
    except Exception as ex:
        logger.error(f"failed to write updated bookmarks file: {ex}")
        logger.error(f"Backup remains at: {backup}")
        return 2

    logger.info(
        f"Synced prefix '{args.prefix}' into Chrome profile '{chrome_profile}'. "
        f"Added: {added}, skipped: {skipped}. Backup: {backup}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="awsurlsync.py",
        description="Generate AWS Switch Role Chrome bookmarks from ~/.aws/config profiles.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level).",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output (ERROR level only).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser(
        "sync",
        help="Sync bookmarks for profiles matching <prefix>-*.",
    )

    sync_parser.add_argument(
        "prefix",
        help="Profile prefix (e.g., 'customer' for profiles 'customer-*').",
    )

    sync_parser.add_argument(
        "--chrome-profile",
        default="Default",
        help="Chrome profile directory name (e.g., 'Default', 'Profile 1').",
    )

    sync_parser.add_argument(
        "--aws-config",
        default=str(aws_config_path()),
        help="Path to AWS config file (default: ~/.aws/config).",
    )

    sync_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not modify Chrome bookmarks; print what would be done.",
    )

    sync_parser.add_argument(
        "--path",
        help=(
            "Bookmark subfolder path under Bookmarks bar, e.g. 'AWS/Customers'. "
            "If not specified, default path is <PREFIX_FIRST_LETTER>/<prefix>."
        ),
    )

    sync_parser.set_defaults(func=cmd_sync)

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


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose, quiet=args.quiet)

    logger.debug("Arguments parsed successfully.")
    logger.debug(f"Command: {args.command}")

    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
