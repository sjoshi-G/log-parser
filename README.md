# Python Log Parser — SSH Brute-Force Detector

Detects SSH brute-force patterns in Linux `auth.log` files: failed logins
clustered from one IP inside a short window. Built as portfolio proof for
the Python / log-analysis skill on my resume — and as a genuinely usable
SOC triage helper.

## What it does (plain language)

When someone tries to break into a server over SSH, they usually try many
passwords quickly from one IP address. That leaves a trail in the server's
`auth.log`: line after line of `Failed password ... from <IP>`.

This script reads that log and answers one question: **did any single IP
fail 5 or more logins within 5 minutes?** If yes, it raises an alert with
the IP, how many failures, and which usernames were targeted.

That is the same logic behind a SIEM brute-force correlation rule — just
written by hand in Python, so you can see exactly how it works.

## What it does NOT do

- It only **detects** — it never blocks an IP, changes a firewall, or
  touches the system it reads from. Read-only and safe to run.
- It only reads `Failed password` lines. Successful logins, other services,
  and other log formats are ignored.
- It is a detector for one attack pattern, not a full SIEM.

## Files

- `log_parser.py` — the script (Python 3, standard library only, nothing to install)
- `sample.log` — synthetic test log (documentation IPs like 203.0.113.x only, no real systems)
- `expected-output.txt` — what `python3 log_parser.py sample.log` prints

## How to run it — step by step

**1. Check Python is installed:**

```bash
python3 --version
```

Any Python 3 version works. No libraries to install — the script uses only
the standard library.

**2. Run it on the sample log:**

```bash
python3 log_parser.py sample.log
```

Expected output:

```
Lines read: 14 | Failed logins: 8 | Unique source IPs: 2
[ALERT] 203.0.113.10: 6 failures in 300s (total 6, users: admin, root, test, ubuntu)
```

What each line means:

- `Lines read: 14` — the script read all 14 lines of the sample file.
- `Failed logins: 8` — 8 of those lines were failed SSH logins.
- `Unique source IPs: 2` — the failures came from 2 different IPs.
- `[ALERT]` — one IP, `203.0.113.10`, failed 6 times inside 5 minutes
  (300 seconds), trying 4 different usernames: admin, root, test, ubuntu.
  Trying many usernames from one IP is a classic brute-force / password-
  spraying pattern.
- The second IP only failed 2 times, below the threshold of 5, so it gets
  no alert — it is counted, not flagged.

**3. Run it on a real log:**

```bash
python3 log_parser.py /var/log/auth.log
```

**4. Save the findings to a file (JSON or CSV):**

```bash
python3 log_parser.py /var/log/auth.log --output findings.json
python3 log_parser.py /var/log/auth.log --output findings.csv
```

The JSON/CSV output is a format a SOC analyst could attach to a ticket or
feed into another tool. In the CSV, the targeted usernames are joined with
`;` so they fit in one column.

**5. Change the sensitivity:**

```bash
python3 log_parser.py /var/log/auth.log --threshold 3 --window 600
```

This flags any IP with 3+ failures inside 10 minutes (600 seconds).
Defaults are `--threshold 5` and `--window 300` (5 failures in 5 minutes).

**6. Logs from another year:**

`auth.log` timestamps have no year (`Oct 14 10:01:02`), so the script
assumes the current year. For an old log file, pass it explicitly:

```bash
python3 log_parser.py old.log --year 2025
```

## How it works — step by step

**Step 1: Match failed logins with a regex.**

Each line is tested against one pattern:

```
Failed password for (invalid user )? <username> from <IP>
```

It handles both log formats:

```
Oct 14 10:01:02 host sshd[123]: Failed password for root from 203.0.113.10 port 22 ssh2
Oct 14 10:01:02 host sshd[123]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2
```

The `(?:invalid user )?` part makes the "invalid user" phrase optional, so
both formats match. Lines that don't match (successful logins, other
services) are skipped.

**Step 2: Parse the timestamp.**

`Oct 14 10:01:02` is converted into a real date/time. Because `auth.log`
has no year, the current year is assumed (overridable with `--year`).
Lines with an unparseable timestamp are skipped.

**Step 3: Group failures by IP, sorted by time.**

All failures from the same IP are collected into one list, sorted oldest
to newest. This turns a flat log file into one timeline per attacker.

**Step 4: Sliding-window check.**

For each IP, the script walks its failures in time order, keeping a
`deque` (a double-ended queue) of timestamps inside the current window:

1. Add the new failure's timestamp to the window.
2. Drop timestamps older than `window` seconds from the newest one
   (they slide out of the window).
3. Record the biggest window size seen — the "peak".

Example with a 300-second window: if an IP fails at 10:00, 10:01, 10:02,
10:03, 10:04, and 10:06, the window at 10:06 holds only the failures from
10:01 onward (5 of them), because the 10:00 failure is more than 300
seconds old. The peak for that IP is 6 (at 10:04, all six were inside
the window).

**Step 5: Flag and report.**

If an IP's peak reaches the threshold (default 5), it becomes a finding
with: IP, total failures, peak failures inside the window, first/last seen
times, and the sorted list of targeted usernames. Findings are printed as
`[ALERT]` lines and, if `--output` is given, written to JSON or CSV.

## Next step

Same detector, new input: parse Windows Security Event 4625 failures
from a Sysmon/Splunk export. That is the follow-up script, not this one.
