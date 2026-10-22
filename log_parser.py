#!/usr/bin/env python3
"""Auth-log brute-force detector — SOC log-analysis starter.

Reads a Linux auth.log-style file, finds source IPs with many failed
password attempts inside a short window, and writes a summary.

Usage:
    python3 log_parser.py sample.log
    python3 log_parser.py /var/log/auth.log --threshold 5 --window 300 --output findings.json
    python3 log_parser.py sample.log --output findings.csv

Sample log lines understood (both formats):
    Oct 14 10:01:02 host sshd[123]: Failed password for root from 203.0.113.10 port 22 ssh2
    Oct 14 10:01:02 host sshd[123]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2

Only the standard library is used. No external dependencies.
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime

# Example: "Oct 14 10:01:02" — auth.log has no year, so assume the current year.
LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


def parse_timestamp(month, day, time_str, year):
    """Convert an auth.log timestamp to a datetime. Returns None if invalid."""
    try:
        return datetime.strptime(
            f"{year}-{MONTHS[month]:02d}-{int(day):02d} {time_str}",
            "%Y-%m-%d %H:%M:%S",
        )
    except (KeyError, ValueError):
        return None


def parse_log(path, year):
    """Return (failures_by_ip, total_failed, lines_read).

    failures_by_ip maps IP -> sorted list of (timestamp, username).
    """
    failures = defaultdict(list)
    total_failed = 0
    lines_read = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            lines_read += 1
            match = LOG_PATTERN.search(line)
            if not match:
                continue
            ts = parse_timestamp(
                match.group("month"), match.group("day"), match.group("time"), year
            )
            if ts is None:
                continue
            total_failed += 1
            failures[match.group("ip")].append((ts, match.group("user")))
    for events in failures.values():
        events.sort()
    return failures, total_failed, lines_read


def find_brute_force(failures, threshold, window_seconds):
    """Sliding-window check: flag an IP when `threshold` failures land
    inside `window_seconds`. Returns a list of finding dicts."""
    findings = []
    for ip, events in failures.items():
        window = deque()  # timestamps inside the current window
        users = set()
        first_seen = events[0][0] if events else None
        last_seen = events[-1][0] if events else None
        peak = 0
        for ts, user in events:
            window.append(ts)
            users.add(user)
            while (ts - window[0]).total_seconds() > window_seconds:
                window.popleft()
            peak = max(peak, len(window))
        if peak >= threshold:
            findings.append({
                "ip": ip,
                "total_failed": len(events),
                "peak_in_window": peak,
                "window_seconds": window_seconds,
                "threshold": threshold,
                "first_seen": first_seen.isoformat() if first_seen else None,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "targeted_users": sorted(users),
            })
    findings.sort(key=lambda f: f["peak_in_window"], reverse=True)
    return findings


def write_output(findings, output_path):
    if output_path is None:
        return
    if output_path.endswith(".csv"):
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "ip", "total_failed", "peak_in_window", "window_seconds",
                "threshold", "first_seen", "last_seen", "targeted_users",
            ])
            writer.writeheader()
            for finding in findings:
                row = dict(finding)
                row["targeted_users"] = ";".join(row["targeted_users"])
                writer.writerow(row)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
    print(f"Wrote {len(findings)} finding(s) to {output_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force patterns in auth.log files."
    )
    parser.add_argument("logfile", help="Path to an auth.log-style file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts inside the window that trigger a finding (default: 5)")
    parser.add_argument("--window", type=int, default=300,
                        help="Sliding window in seconds (default: 300 = 5 minutes)")
    parser.add_argument("--output", help="Optional .json or .csv file for findings")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="Year to assume for log timestamps (auth.log has no year)")
    args = parser.parse_args(argv)

    try:
        failures, total_failed, lines_read = parse_log(args.logfile, args.year)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        return 1

    findings = find_brute_force(failures, args.threshold, args.window)

    print(f"Lines read: {lines_read} | Failed logins: {total_failed} | "
          f"Unique source IPs: {len(failures)}")
    if not findings:
        print(f"No IP hit {args.threshold}+ failures in {args.window}s. No brute force found.")
    for finding in findings:
        print(f"[ALERT] {finding['ip']}: {finding['peak_in_window']} failures "
              f"in {finding['window_seconds']}s "
              f"(total {finding['total_failed']}, users: {', '.join(finding['targeted_users'])})")
    write_output(findings, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
