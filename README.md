integrity-check — Log File Integrity Verification Tool

A command-line tool that detects unauthorized tampering of log files using
SHA-256 hashing. Built as a hands-on introduction to File Integrity
Monitoring (FIM) — the same underlying technique used by real tools like
Tripwire, OSSEC, and Wazuh.

Why this matters

When an attacker breaches a system, one of the first things they often try
to do is cover their tracks by editing or deleting log files. FIM tools
exist to catch exactly that: if a log's hash changes without an authorized
update, it's evidence of tampering.

How it works

1. **`init`** — computes a SHA-256 hash for every file at the given path and
   stores it as the trusted baseline.
2. **`check`** — recomputes the hash(es) and compares against the baseline,
   reporting `Unmodified`, `Modified (Hash mismatch)`, `Not tracked`, or
   `Missing`.
3. **`update`** — manually resets the baseline for a file, e.g. after a
   legitimate log rotation or an authorized change.

Where the hashes are stored (and why it matters)

The baseline is stored at `~/.log_integrity_store.json` — **outside** the
directory being monitored, with file permissions locked to owner-only
(`600`). This is a deliberate security decision: if the hash store lived
inside `/var/log` next to the logs themselves, an attacker who can modify a
log file could just as easily modify the stored hash to match, defeating
the entire purpose of the tool. Keeping it separate (and ideally on a
system only a trusted admin account can write to) is what makes the
baseline meaningful.

Setup

```bash
chmod +x integrity-check.py
# Optional: rename/alias so it matches the spec's example usage
mv integrity-check.py integrity-check
```

Usage

```bash
# Initialize — store hashes of all log files in a directory
./integrity-check init /var/log
# Output: Hashes stored successfully. (N file(s) baselined)

# Check a single file
./integrity-check check /var/log/syslog
# Output: Status: Modified (Hash mismatch)

./integrity-check check /var/log/auth.log
# Output: Status: Unmodified

# Check an entire directory, with a detailed breakdown of what changed
./integrity-check check /var/log --report

# Manually re-initialize a single file after a legitimate change
./integrity-check update /var/log/syslog
# Output: Hash updated successfully.
```

Exit codes

`check` returns a non-zero exit code (`2`) when tampering or missing files
are detected — this lets you plug it into a cron job or monitoring script
and get alerted automatically:

```bash
# Example: run every hour via cron, email on failure
0 * * * * /path/to/integrity-check check /var/log || mail -s "Log tampering detected" admin@example.com
```

 Concepts demonstrated

- **Cryptographic hashing** (SHA-256) as a tamper-detection mechanism
- **Secure storage of trust data** — keeping the baseline separate from
  and more protected than the data it verifies
- **CLI tool design** with subcommands (`init` / `check` / `update`)
- **File Integrity Monitoring (FIM)** — a real control used in SOC/blue
  team environments and required by compliance frameworks like PCI-DSS
  and HIPAA

Limitations (worth mentioning in your write-up)

- This is a learning tool, not production-grade. A real deployment would
  need the baseline store on a separate, hardened system (or write-once
  storage) so a fully compromised host can't also tamper with it.
- No real-time monitoring — this checks integrity at the moment you run
  it, not continuously. Production FIM tools use OS-level file watchers.
- Log rotation will trigger false "Missing"/"Modified" results unless you
  run `update` after each rotation — worth discussing as a real
  operational challenge FIM tools have to solve.

 Project page
Project page: https://roadmap.sh/projects/file-integrity-checker
