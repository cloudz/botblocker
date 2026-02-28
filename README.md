# 🛡️ BotBlocker

> A lightweight, persistent Go daemon that detects bad bots attacking shared hosting servers and blocks them automatically via CSF firewall.

**Stack:** Go · CSF · nginx · Apache · DirectAdmin · CloudLinux
**Version:** 1.0.0
**Binary size:** ~2.4MB · **RAM usage:** ~8–12MB at runtime

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Security Hardening](#security-hardening)
- [Setup & Installation](#setup--installation)
- [Configuration Reference](#configuration-reference)
- [Scoring System](#scoring-system)
- [Block Escalation](#block-escalation)
- [File Structure](#file-structure)
- [Operations & Commands](#operations--commands)
- [Quick Reference](#quick-reference)
- [Tuning Guide](#tuning-guide)

---

## Overview

On a shared hosting server, a single scanner can simultaneously target hundreds of hosted domains — causing a server load spike and a flood of `403`/`404` errors across all sites. BotBlocker watches for exactly this pattern, identifies the offending IPs from the logs, and blocks them via CSF within a single poll cycle (default: 10 seconds).

```
┌─────────────────────────────────────────────────────────┐
│                    botblocker daemon                     │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐   ┌────────────┐  │
│  │ Load Monitor │───▶│  Log Parser  │──▶│  IP Scorer │  │
│  └──────────────┘    └──────────────┘   └────────────┘  │
│         │                                      │         │
│         ▼                                      ▼         │
│  ┌──────────────┐                    ┌──────────────┐    │
│  │ Trigger Gate │                    │ Block Engine │    │
│  └──────────────┘                    └──────────────┘    │
│                                               │          │
└───────────────────────────────────────────────┼─────────┘
                                                │
                          ┌─────────────────────▼──────┐
                          │            CSF              │
                          │   csf -td <ip> <ttl>        │
                          │   csf -d <ip>               │
                          └─────────────────────────────┘
```

---

## Architecture

The daemon is split into six focused packages:

| Package | File | Responsibility |
|---|---|---|
| `monitor` | `monitor.go` | Watches `/proc/loadavg`, fires triggers |
| `parser` | `parser.go` | Reads & parses nginx + Apache logs |
| `scorer` | `scorer.go` | Scores IPs on 6 threat signals |
| `blocker` | `blocker.go` | Whitelist, repeat-offender state, CSF calls |
| `config` | `config.go` | Loads `config.ini`, applies defaults |
| `logger` | `logger.go` | Structured logging to daemon + block log |

### Two-tier trigger system

```
Every 10s ──▶ Check /proc/loadavg
                    │
          ┌─────────▼──────────┐
          │  load > cores×1.5? │
          └─────────┬──────────┘
                    │ YES               Every 10min
                    ▼                       │
             ┌─────────────────────────────▼──┐
             │         Parse Cycle             │
             │  glob logs → score → block      │
             └─────────────────────────────────┘
```

The load check is intentionally cheap — just reading a number from `/proc/loadavg`. The expensive log parsing only runs when genuinely needed.

---

## How It Works

### 1. Load Monitor

Reads the 1-minute load average from `/proc/loadavg` on every poll tick. If it exceeds `CPU cores × load_multiplier`, a parse cycle is triggered.

A **cooldown** prevents the same spike from triggering multiple overlapping parse cycles. Once triggered, the monitor won't re-trigger for 5 minutes even if load stays high.

A **baseline scan** runs every 10 minutes regardless, to catch slow scanners that don't spike load.

### 2. Log Parser

Discovers log files via glob patterns:

- **Nginx:** `/var/log/nginx/access.log`
- **Apache/DirectAdmin:** `/home/*/domains/*/logs/access.log`

Both use the standard **Combined Log Format**. The parser also handles **Cloudflare's `CF-Connecting-IP`** header, extracting the real visitor IP rather than Cloudflare's proxy IP.

Per-domain Apache logs in DirectAdmin automatically reveal which vhost is being targeted, which feeds into the multi-vhost scoring signal.

> **Note:** The parser only reads lines within the configured `log_parse_window` (default: last 5 minutes). Lines older than this are skipped, keeping each cycle fast even on large log files.

### 3. IP Scorer

Each IP seen in the parse window is scored on 6 weighted signals:

| Signal | Default Points |
|---|---|
| High request rate (`>50 req/min`) | +30 |
| High error rate (`>80% 4xx`) | +25 |
| Known scanner User-Agent | +20 |
| Honeypot path hit | +40 |
| Multi-vhost scan (`≥3 domains`) | +15 |
| Known scanner path patterns | +10–20 |

**Block threshold: 60 points** (configurable).

### 4. Block Engine

Before calling CSF, the blocker runs through 5 gates:

1. Validates the IP string against both `net.ParseIP()` and a strict character regex — raw log data is **never** passed to a shell
2. Checks the **whitelist** (Cloudflare ranges, search engine bots, your office IPs)
3. Checks whether the IP is already blocked (temp or permanent)
4. Enforces a **rate limit of 20 blocks/minute** to prevent log-poisoning attacks
5. Decides temp vs. permanent based on repeat-offender count

CSF is called via `exec.Command` with separate arguments — IP strings are never concatenated into a shell command string.

---

## Security Hardening

BotBlocker includes several layers of defense-in-depth beyond the basic blocking logic:

### Command injection prevention

IP strings pass through two validation gates before reaching CSF: Go's `net.ParseIP()` for semantic validation, and a strict character-class regex (`^(\d{1,3}\.){3}\d{1,3}$` for IPv4, `^[0-9a-fA-F:]+$` for IPv6) for syntactic validation. CSF is invoked with `exec.Command` using separate arguments — no shell interpolation.

### Log injection / poisoning protection

- All parsed log fields (method, path, UA) are sanitised: control characters are stripped and fields are length-truncated
- Individual log lines are capped at 8 KB; lines exceeding this are silently dropped
- A hard cap of 500,000 lines per file prevents memory exhaustion from crafted giant log files
- For log files larger than 50 MB, the parser seeks to the tail rather than reading from the start

### Anti-flood rate limit

A maximum of 20 blocks per minute prevents an attacker from spoofing thousands of "bad" source IPs in log data to trigger a CSF flood that would lock out legitimate traffic or DoS the firewall itself.

### Atomic state persistence

`state.json` is written via write-to-temp-then-rename, so a crash or power loss mid-write cannot corrupt the offender history.

### Systemd hardening

The service unit runs with restrictive systemd security directives:

- `ProtectSystem=strict` — filesystem is read-only except explicitly allowed paths
- `ProtectHome=read-only` — home directories are read-only (needed for DirectAdmin log access)
- `ReadWritePaths` limited to `/var/log/botblocker` and `/var/lib/botblocker`
- `PrivateTmp=true` — isolated `/tmp` namespace
- `MemoryDenyWriteExecute=true` — prevents runtime code generation
- `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups` — blocks kernel-level changes
- `MemoryMax=128M` — hard memory ceiling

### Whitelist hot-reload

The whitelist file is re-read on every parse cycle, so edits take effect without a daemon restart. This reduces lockout risk during incident response.

---

## Setup & Installation

### Prerequisites

- Go 1.21+ on your build machine
- CSF installed at `/usr/sbin/csf`
- Root access on the target server

### Build

```bash
cd botblocker

# Native build (when building on the target Linux server)
go build -ldflags="-s -w" -o botblocker ./cmd/botblocker

# Cross-compile from macOS to Linux (amd64)
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o botblocker ./cmd/botblocker

# Cross-compile from macOS to Linux (arm64, e.g. AWS Graviton)
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o botblocker ./cmd/botblocker
```

> **Tip:** If you see `cannot execute binary file: Exec format error` on the server, you built for the wrong architecture. Check with `uname -m` on the server: `x86_64` → `GOARCH=amd64`, `aarch64` → `GOARCH=arm64`.

### Install

```bash
# Edit the whitelist BEFORE installing — add your own IPs
nano whitelist.txt

# Run installer (as root)
bash scripts/install.sh
```

The installer:
- Copies the binary to `/usr/local/bin/botblocker`
- Installs config, whitelist, and honeypot paths to `/usr/local/botblocker/`
- Creates log directories under `/var/log/botblocker/`
- Installs and enables the systemd service
- Starts the daemon immediately

> **Warning:** Add your own static IPs to `whitelist.txt` **before** running the installer. Failing to do this risks locking yourself out if your own traffic pattern looks suspicious.

### Test before going live

```bash
# Single scan cycle — prints what would be blocked, does not call CSF
botblocker --once --config /usr/local/botblocker/config.ini
```

---

## Configuration Reference

Config file location: `/usr/local/botblocker/config.ini`

### `[general]`

| Key | Default | Description |
|---|---|---|
| `poll_interval` | `10` | Seconds between load checks |
| `log_parse_window` | `300` | Seconds of log history to analyse |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` |

### `[thresholds]`

| Key | Default | Description |
|---|---|---|
| `load_multiplier` | `1.5` | Trigger when load > `cores × this` |
| `block_score` | `60` | Minimum score to block |
| `requests_per_minute` | `50` | Req/min for rate score |
| `error_rate_pct` | `80` | % of 4xx for error score |
| `repeat_offender_n` | `3` | Temp blocks before permanent |
| `temp_block_seconds` | `3600` | TTL for temporary blocks (1 hour) |

### `[paths]`

| Key | Default |
|---|---|
| `nginx_log_glob` | `/var/log/nginx/access.log` |
| `apache_log_glob` | `/home/*/domains/*/logs/access.log` |
| `whitelist_file` | `/usr/local/botblocker/whitelist.txt` |
| `blocked_log` | `/var/log/botblocker/blocked.log` |
| `daemon_log` | `/var/log/botblocker/botblocker.log` |
| `state_file` | `/var/lib/botblocker/state.json` |
| `honeypot_paths` | `/usr/local/botblocker/honeypot_paths.txt` |

### `[csf]`

| Key | Default |
|---|---|
| `csf_bin` | `/usr/sbin/csf` |

### `[scoring]`

| Key | Default | Trigger |
|---|---|---|
| `high_request_rate` | `30` | Req/min exceeds threshold |
| `high_error_rate` | `25` | 4xx rate exceeds threshold |
| `known_scanner_ua` | `20` | UA matches scanner patterns |
| `honeypot_path_hit` | `40` | Request to a honeypot path |
| `multi_vhost_scan` | `15` | Requests across multiple domains |
| `cross_domain_thresh` | `3` | Min domains to trigger multi-vhost |

---

## Scoring System

### How a score is built

```
IP: 198.51.100.7
─────────────────────────────────────────────────────
Signal                          Points
─────────────────────────────────────────────────────
80 req/min   (threshold: 50)    +30
100% error rate (80/80 reqs)    +25
Scanner UA: python-requests     +20
Honeypot hit: /.env             +40
─────────────────────────────────────────────────────
Total score                     115  ✦ BLOCK (≥60)
```

### Known scanner User-Agents

The following UA patterns are flagged automatically:

`nuclei` · `zgrab` · `masscan` · `nmap` · `nikto` · `sqlmap` · `dirbuster` · `gobuster` · `wfuzz` · `hydra` · `burpsuite` · `acunetix` · `nessus` · `openvas` · `python-requests` · `go-http-client` · `scrapy` · `libwww-perl` · `metasploit`

> **Tip:** `curl` and `wget` are also flagged. If you have legitimate automated scripts using these, either whitelist their source IPs or raise the `known_scanner_ua` threshold so they need other signals to trigger a block.

> **Note:** Requests with an **empty or missing User-Agent** are also flagged as `empty-ua`. If you have internal health checks or monitoring tools that send requests without a UA, whitelist their source IPs.

### Honeypot paths

Paths in `honeypot_paths.txt` are ones no legitimate visitor ever requests. Examples:

- `/.env` — environment file exposure
- `/wp-login.php` — WordPress login (on non-WP sites)
- `/.git/config` — source control exposure
- `/actuator/env` — Spring Boot probes
- `/shell.php`, `/c99.php` — webshell probes
- `/.aws/credentials` — cloud credential fishing

Add or remove paths from `honeypot_paths.txt` to match your hosting environment.

---

## Block Escalation

```
First offence:
  IP scores ≥ 60
      │
      ▼
  csf -td <ip> 3600 BotBlocker   ← temporary block (1 hour)
  OffenderCount[ip]++               (persisted to state.json)

Second & third offence:
  Same as above — OffenderCount keeps incrementing

Fourth offence (repeat_offender_n = 3):
  IP scores ≥ 60 again
      │
      ▼
  csf -d <ip> BotBlocker-permanent   ← permanent block
  Moved to PermanentBlocked map
```

State is written to `/var/lib/botblocker/state.json` after every block action and survives daemon restarts.

> **Note:** The offender count does **not** reset between temporary blocks. A scanner that keeps coming back will escalate to permanent regardless of how long they waited between attacks.

---

## File Structure

```
/usr/local/bin/
└── botblocker                  ← compiled binary

/usr/local/botblocker/
├── config.ini                  ← all tunable settings
├── whitelist.txt               ← IPs/CIDRs never to block
└── honeypot_paths.txt          ← paths that trigger penalty score

/var/log/botblocker/
├── botblocker.log              ← daemon activity
└── blocked.log                 ← one structured line per block action

/var/lib/botblocker/
└── state.json                  ← repeat-offender counts (persistent)

/etc/systemd/system/
└── botblocker.service          ← systemd unit
```

### blocked.log format

```
[2024-01-25 14:32:10] ACTION=BLOCK TYPE=TEMP IP=203.0.113.42 SCORE=115 TTL=3600s REASON="80 req/min; 100% error rate; scanner UA; honeypot hit"
[2024-01-25 16:45:02] ACTION=BLOCK TYPE=PERMANENT IP=203.0.113.42 SCORE=95 TTL=permanent REASON="multi-vhost scan; honeypot hit"
[2024-01-25 16:45:02] ACTION=UNBLOCK IP=198.51.100.1
```

---

## Operations & Commands

### Service management

```bash
systemctl status botblocker       # check daemon is running
systemctl restart botblocker      # restart after config change
systemctl stop botblocker         # stop the daemon
journalctl -u botblocker -f       # follow systemd journal
```

### Log monitoring

```bash
# Watch block events in real time
tail -f /var/log/botblocker/blocked.log

# Watch daemon activity
tail -f /var/log/botblocker/botblocker.log

# Count blocks in the last 24h
grep "$(date '+%Y-%m-%d')" /var/log/botblocker/blocked.log | wc -l

# List permanently blocked IPs from our log
grep "TYPE=PERMANENT" /var/log/botblocker/blocked.log | awk '{print $4}' | cut -d= -f2
```

### Manual controls

```bash
# Force an immediate scan without restarting
kill -USR1 $(pidof botblocker)

# Run a single scan cycle (dry-run friendly — check logs after)
botblocker --once

# Run with a different config
botblocker --config /path/to/other.ini

# Check version
botblocker --version
```

### CSF manual operations

```bash
# Check if a specific IP is blocked
csf -g 203.0.113.42

# Manually unblock an IP
csf -dr 203.0.113.42       # remove from deny list
csf -tr 203.0.113.42       # remove from temp block

# View all temp blocks
csf -t

# View deny list
cat /etc/csf/csf.deny | grep BotBlocker
```

### Whitelist management

```bash
# Add an IP to the whitelist and reload
echo "1.2.3.4  # My office" >> /usr/local/botblocker/whitelist.txt
kill -USR1 $(pidof botblocker)   # daemon re-reads whitelist on each cycle
```

> **Warning:** The whitelist is read fresh on every parse cycle, so you don't need to restart the daemon after editing it. However, if an IP is already in CSF's deny list, you'll need to manually run `csf -dr <ip>` to unblock it — BotBlocker does not manage existing CSF rules, only adds new ones.

---

## Quick Reference

| Task | Command |
|---|---|
| Force immediate scan | `kill -USR1 $(pidof botblocker)` |
| One-shot scan | `botblocker --once` |
| Watch blocks live | `tail -f /var/log/botblocker/blocked.log` |
| Unblock an IP | `csf -dr <ip>` |
| Check if IP is blocked | `csf -g <ip>` |
| Restart after config change | `systemctl restart botblocker` |
| View repeat offenders | `cat /var/lib/botblocker/state.json` |
| Add IP to whitelist | `echo "<ip>" >> /usr/local/botblocker/whitelist.txt` |

---

## Tuning Guide

### Reducing false positives

If legitimate tools or services are getting blocked, adjust the scoring weights in `config.ini`:

```ini
[scoring]
# Raise this if your own automation uses curl/wget
known_scanner_ua = 35

# Raise this if you have APIs with high 404 rates (e.g. REST not-found responses)
high_error_rate = 35

# Raise the overall block threshold
[thresholds]
block_score = 80
```

### Aggressive mode (under active attack)

```ini
[thresholds]
load_multiplier = 1.0          # trigger on any load elevation
block_score = 40               # lower bar to block
temp_block_seconds = 86400     # 24h temp blocks
repeat_offender_n = 2          # permanent after 2 strikes

[general]
poll_interval = 5              # check load every 5s
log_parse_window = 600         # look back 10 minutes
```

### CloudLinux note

CloudLinux's LVE limits per-user CPU so a single targeted domain may not spike the whole-server load average. If you find load stays low despite an obvious attack on one domain, lower `load_multiplier` or rely on the 10-minute baseline scan. You can also monitor per-user LVE stats with `lveps` and correlate with which domain's log is showing the traffic.

### Cloudflare note

If a domain uses Cloudflare, the real visitor IP arrives in the `CF-Connecting-IP` header. BotBlocker handles this automatically — it detects the Cloudflare log format and extracts the real IP rather than blocking Cloudflare's proxy servers. Cloudflare's IPv4 and IPv6 ranges are pre-populated in `whitelist.txt`.

---

## License

MIT
