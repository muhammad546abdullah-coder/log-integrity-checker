#!/usr/bin/env python3
"""
integrity-check — Log File Integrity Verification Tool
---------------------------------------------------------
Detects unauthorized tampering of log files using SHA-256 hashing.

Commands:
    init <path>     Compute and store baseline hashes for a file or directory
    check <path>    Compare current hash(es) against the stored baseline
    update <path>   Manually re-initialize (reset) the baseline for a file

The hash store is kept OUTSIDE the monitored directory, at:
    ~/.log_integrity_store.json
with permissions restricted to the owner (600). This matters: if an
attacker can modify a log file, you don't want them able to just as
easily rewrite the hash record sitting next to it.

Usage:
    ./integrity-check init /var/log
    ./integrity-check check /var/log/syslog
    ./integrity-check check /var/log --report
    ./integrity-check update /var/log/syslog
"""

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime

STORE_PATH = os.path.expanduser("~/.log_integrity_store.json")


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def compute_hash(filepath: str, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """Compute the hash of a single file, reading in chunks to handle large logs safely."""
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
    except (PermissionError, FileNotFoundError, OSError):
        return None
    return hasher.hexdigest()


def collect_files(path: str) -> list:
    """Return a list of absolute file paths — handles both a single file and a directory."""
    path = os.path.abspath(path)
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        files = []
        for root, _, filenames in os.walk(path):
            for name in filenames:
                files.append(os.path.join(root, name))
        return files
    return []


# ---------------------------------------------------------------------------
# Secure hash store
# ---------------------------------------------------------------------------

def load_store() -> dict:
    """Load the hash store. Returns an empty dict if it doesn't exist yet."""
    if not os.path.exists(STORE_PATH):
        return {}
    with open(STORE_PATH, "r") as f:
        return json.load(f)


def save_store(store: dict):
    """Save the hash store and lock down its permissions to owner-only (600)."""
    with open(STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)
    os.chmod(STORE_PATH, stat.S_IRUSR | stat.S_IWUSR)  # rw for owner only


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(path: str, algorithm: str):
    files = collect_files(path)
    if not files:
        print(f"Error: no files found at '{path}'.")
        sys.exit(1)

    store = load_store()
    count = 0
    for filepath in files:
        file_hash = compute_hash(filepath, algorithm)
        if file_hash is None:
            print(f"  [skip] Could not read: {filepath}")
            continue
        store[filepath] = {
            "hash": file_hash,
            "algorithm": algorithm,
            "initialized_at": datetime.now().isoformat(),
        }
        count += 1

    save_store(store)
    print(f"Hashes stored successfully. ({count} file(s) baselined)")


def cmd_check(path: str, report: bool):
    files = collect_files(path)
    if not files:
        print(f"Error: no files found at '{path}'.")
        sys.exit(1)

    store = load_store()
    mismatches = []
    not_tracked = []

    single_file = len(files) == 1

    for filepath in files:
        record = store.get(filepath)
        if record is None:
            not_tracked.append(filepath)
            if single_file:
                print("Status: Not tracked (run 'init' on this file first)")
            continue

        current_hash = compute_hash(filepath, record["algorithm"])
        if current_hash is None:
            print(f"Status: Missing or unreadable — {filepath}")
            mismatches.append(filepath)
            continue

        if current_hash == record["hash"]:
            if single_file:
                print("Status: Unmodified")
        else:
            mismatches.append(filepath)
            if single_file:
                print("Status: Modified (Hash mismatch)")

    # Check for tracked files that no longer exist on disk (possible deletion/tampering)
    if not single_file:
        tracked_under_path = [f for f in store if f.startswith(os.path.abspath(path))]
        missing = [f for f in tracked_under_path if f not in files]

        print(f"Checked {len(files)} file(s).")
        print(f"  Modified:    {len(mismatches)}")
        print(f"  Not tracked: {len(not_tracked)}")
        print(f"  Missing:     {len(missing)}")

        if report:
            if mismatches:
                print("\n[!] Modified files (hash mismatch):")
                for f in mismatches:
                    print(f"    ~ {f}")
            if missing:
                print("\n[!] Missing files (tracked previously, now gone):")
                for f in missing:
                    print(f"    - {f}")
            if not_tracked:
                print("\n[?] Not tracked (never initialized):")
                for f in not_tracked:
                    print(f"    ? {f}")

        if mismatches or missing:
            sys.exit(2)  # non-zero exit code so this can be used in scripts/cron/alerts


def cmd_update(path: str, algorithm: str):
    files = collect_files(path)
    if not files:
        print(f"Error: no files found at '{path}'.")
        sys.exit(1)

    store = load_store()
    for filepath in files:
        file_hash = compute_hash(filepath, algorithm)
        if file_hash is None:
            print(f"Error: could not read {filepath}")
            continue
        store[filepath] = {
            "hash": file_hash,
            "algorithm": algorithm,
            "initialized_at": datetime.now().isoformat(),
        }

    save_store(store)
    print("Hash updated successfully.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="integrity-check",
        description="Verify log file integrity using cryptographic hashing.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init", help="Store baseline hashes for a file or directory")
    p_init.add_argument("path", help="Log file or directory to initialize")
    p_init.add_argument("--algorithm", default="sha256", help="Hash algorithm (default: sha256)")

    p_check = subparsers.add_parser("check", help="Check current hashes against the stored baseline")
    p_check.add_argument("path", help="Log file or directory to check")
    p_check.add_argument("--report", action="store_true", help="List which files mismatched")

    p_update = subparsers.add_parser("update", help="Manually re-initialize the baseline for a file")
    p_update.add_argument("path", help="Log file or directory to update")
    p_update.add_argument("--algorithm", default="sha256", help="Hash algorithm (default: sha256)")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args.path, args.algorithm)
    elif args.command == "check":
        cmd_check(args.path, args.report)
    elif args.command == "update":
        cmd_update(args.path, args.algorithm)


if __name__ == "__main__":
    main()