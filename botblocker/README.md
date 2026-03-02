# BotBlocker

Automated bot and vulnerability scanner detection and blocking for Linux servers running Nginx/Apache with CSF firewall. Designed for DirectAdmin environments but works with any standard access log format.

BotBlocker monitors server load and, when thresholds are exceeded, parses recent access logs to identify and block malicious IPs via CSF (ConfigServer Firewall). By default it runs a single dry-run scan and exits — use `--daemon` for continuous monitoring.

## Features

- **Multi-signal scoring** — combines request rate, error rate, scanner UA detection, honeypot path hits, multi-vhost scanning, and known attack path patterns into a single threat score per IP
- **CSF integration** — temporary and permanent blocks via `csf -td` / `csf -d` with repeat offender escalation
- **Load-triggered scanning** — daemon mode only parses logs when server load exceeds a configurable threshold (CPUs x multiplier)
- **`--once` mode** — dry-run analysis with a sorted threat report, blocks nothing
- **`--scan` mode** — one-shot analysis that actually blocks via CSF (the "under attack, do it now" command)
- **`--window` override** — analyze a custom time window (e.g., last hour) instead of the default 5 minutes
- **Whitelist support** — IPs/CIDRs in the whitelist file are never blocked; server's own IPs are auto-whitelisted at startup
- **Honeypot paths** — configurable trap paths that boost scoring when accessed
- **Rate limiting** — max 20 blocks per minute to prevent log-poisoning attacks
- **State persistence** — tracks repeat offenders across restarts

## Installation

```bash
# Build (cross-compile for Linux x86_64 from any platform)
cd botblocker
GOOS=linux GOARCH=amd64 go build -o botblocker ./cmd/botblocker

# Deploy
scp botblocker root@server:/usr/local/botblocker/
scp config.ini root@server:/usr/local/botblocker/config.ini
```

## Usage

```bash
# Analyze — see report, block nothing (default behavior)
botblocker --config /usr/local/botblocker/config.ini

# Analyze last hour of logs
botblocker --once --window 3600

# Under attack — analyze AND block immediately
botblocker --scan --config /usr/local/botblocker/config.ini

# Block based on last 30 minutes
botblocker --scan --window 1800

# Run as daemon (blocks automatically when load spikes)
botblocker --daemon --config /usr/local/botblocker/config.ini

# Force immediate scan on running daemon
kill -USR1 $(pidof botblocker)
```

## Example output (`--once`)

```
[2026-03-02 06:40:36] INFO parsed 10534 log entries from within the last 300s

     IP                 SCORE   REQS REQ/MIN  ERR% DOMAINS  REASONS
------------------------------------------------------------------------------------------
>>   xx.xx.32.183         125    315      63  100%       1  63 req/min; 100% error rate; scanner UA: empty-ua; honeypot hit: /wp-includes/; scanner paths: /wp-admin, /xmlrpc.php, /cgi-bin/
>>   xx.xx.57.125         125    315      63  100%       1  63 req/min; 100% error rate; scanner UA: empty-ua; honeypot hit: /wp-includes/; scanner paths: /wp-admin, /xmlrpc.php, /cgi-bin/
>>   2a01:4f8:xxxx:xxxx::2  115   1081     216    1%      26  216 req/min; scanner UA: empty-ua; honeypot hit: /wp-admin/; 26 domains scanned; scanner paths: /wp-admin
>>   xx.xx.126.185        110    561     112   99%       1  112 req/min; 99% error rate; honeypot hit: /pma/; scanner paths: /phpmyadmin, /wp-admin, /.env
>>   xx.xx.32.134         110    360      72  100%       1  72 req/min; 100% error rate; honeypot hit: /wp-includes/; scanner paths: /wp-admin, /vendor/phpunit, /cgi-bin/
>>   xx.xx.32.172         110   1986     397  100%       1  397 req/min; 100% error rate; honeypot hit: /wp-admin/; scanner paths: /wp-login.php, /cgi-bin/, /shell, /c99, /wp-admin, /vendor/phpunit
>>   xx.xx.70.12          100   1073     215   33%       2  215 req/min; scanner UA: empty-ua; honeypot hit: /wp-includes/; scanner paths: /wp-admin, /xmlrpc.php, /cgi-bin/
>>   xx.xx.70.202          90      9       2  100%       3  100% error rate; honeypot hit: /xmlrpc.php; 3 domains scanned; scanner paths: /xmlrpc.php
>>   xx.xx.41.168          85     76      15  100%       2  100% error rate; scanner UA: empty-ua; honeypot hit: /wp-includes/
>>   xx.xx.137.52          85    717     143  100%       1  143 req/min; 100% error rate; scanner UA: empty-ua; scanner paths: /wp-admin, /cgi-bin/
>>   xx.xx.173.41          80     72      14   92%       1  92% error rate; honeypot hit: /console/; scanner paths: /.git/, /actuator/, /console/, /.env
>>   xx.xx.111.158         80    324      65    4%       2  65 req/min; honeypot hit: /wp-login.php; scanner paths: /wp-login.php
>>   xx.xx.249.162         75      6       1  100%       1  100% error rate; honeypot hit: /wp-admin/; scanner paths: /wp-admin
>>   xx.xx.220.116         70    717     143    3%       1  143 req/min; honeypot hit: /wp-content/uploads/
     xx.xx.61.118          50      2       0  100%       2  honeypot hit: /xmlrpc.php; scanner paths: /xmlrpc.php
     xx.xx.25.215          50      2       0  100%       1  honeypot hit: /wp-login.php; scanner paths: /wp-login.php
     xx.xx.141.89          50      2       0    0%       1  honeypot hit: /wp-login.php; scanner paths: /wp-login.php
     ...
------------------------------------------------------------------------------------------
Total: 72 scored, 14 above block threshold (60)
```

IPs marked with `>>` exceed the block threshold and would be blocked in `--scan` mode. IPs marked with `WL` are whitelisted and will never be blocked.

## Configuration

See [`config.ini`](config.ini) for all options. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `poll_interval` | `10` | Seconds between load checks (daemon mode) |
| `log_parse_window` | `300` | Seconds of log history to analyze |
| `load_multiplier` | `1.5` | Trigger when load > CPUs x this value |
| `block_score` | `60` | Minimum combined score to block an IP |
| `requests_per_minute` | `50` | RPM threshold for rate scoring |
| `error_rate_pct` | `80` | 4xx error % threshold |
| `repeat_offender_n` | `3` | Temp blocks before permanent ban |
| `temp_block_seconds` | `3600` | TTL for temporary blocks |

### Scoring signals

| Signal | Default points | Trigger |
|--------|---------------|---------|
| High request rate | 30 | Exceeds `requests_per_minute` |
| High error rate | 25 | Exceeds `error_rate_pct` with 5+ requests |
| Known scanner UA | 20 | Matches nuclei, zgrab, sqlmap, empty UA, etc. |
| Honeypot path hit | 40 | Requests a configured honeypot path |
| Multi-vhost scan | 15 | Hits 3+ different domains |
| Scanner paths | 10-20 | Known attack paths (wp-admin, .env, .git, etc.) |

## Requirements

- Linux server with CSF (ConfigServer Firewall) installed
- Nginx and/or Apache access logs in Combined Log Format
- Go 1.21+ (build only)
