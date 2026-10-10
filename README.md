# pfSense Log Capture

Lightweight UDP syslog capture and a security **digest** for a pfSense firewall.
Two stdlib-based Python tools plus a `config.yaml` for timings and
include/exclude filters:

- **`receiver.py`** — continuous listener. Binds a UDP port, writes everything
  pfSense forwards to a rotating log file. Good for long-running capture.
- **`digest.py`** — ephemeral snapshot for **cron**. Listens for a short window,
  prints a small bounded WAN security summary to stdout, deletes the raw capture
  before it exits. Nothing persists between runs.

The digest surfaces the signals that actually matter and drops the noise:

- Suricata IDS/IPS **alerts** (severity, signature, src→dst, proto, category)
- WAN **DNS queries**, with weird-TLD / very-long-label domains flagged
- **filterlog** block/pass counts, top blocked external scanners, top WAN dst ports
- Internal→external egress on **non-standard ports** (possible C2 / odd conns)
- Dropped noise: `sendto: Host is down` spam, MQTT/meshtastic chatter, LAN-interface traffic

## Requirements

- Python 3.8+ (stdlib)
- PyYAML — `pip install -r requirements.txt`

No external services or dependencies beyond PyYAML.

## Quick start

### 1. Point pfSense at this box

On the firewall: **Status → System Logs → Settings → Remote syslog servers**
→ add `<this box's IP>:<listen.port>` (default `42069`). pfSense *pushes*
syslog over UDP; there is no pull API.

### 2. Configure

Edit `config.yaml` — bind address/port, capture timings, interface names, and
the include/exclude lists. LAN IPs, hostnames, and noisy source IPs are yours
to fill in (they were scrubbed from this repo; ports are kept as-is).

### 3. Continuous capture (optional)

```bash
python3 receiver.py                      # uses config.yaml
python3 receiver.py --port 5514          # override the port
python3 receiver.py --dump /var/log/pfsense.log --only-wan
```

Verify it's bound (UDP silently drops to an unbound port):
`ss -uln | grep :42069`.

### 4. Ephemeral digest (the cron job)

```bash
python3 digest.py                        # short WAN summary on stdout
python3 digest.py --seconds 60           # longer window
timeout 12 python3 digest.py --keep-raw  # debug: keep the raw capture
```

See `cron.example.sh` for a scheduler wrapper. The job runs `digest.py` on an
interval and ships the rendered digest wherever you want (email, XMPP,
Discord, a file via `cron.state_file`, …). Delivery is configured on the
scheduler side, not in `config.yaml`.

## Configuration (`config.yaml`)

| Section | Key | Meaning |
|---|---|---|
| `listen` | `host`, `port` | UDP bind address and syslog receive port |
| `receiver` | `dump`, `max_size` | log file path and rotation threshold (bytes) |
| `digest` | `seconds` | hard wall-clock cap on the capture window |
| `digest` | `target_digest` | stop early once the digest reaches this many bytes |
| `digest` | `max_raw` | safety ceiling on captured raw bytes |
| `digest` | `max_alerts/domains/scanners/ports/egress` | caps on each digest section |
| `interface` | `wan`, `lan` | interface names; digest keeps WAN lines only |
| `include` | `only_wan` | restrict to WAN-interface traffic |
| `exclude` | `src_ips` | drop packets from these senders |
| `exclude` | `substrings` | drop lines containing any of these (case-insensitive) |
| `exclude` | `ports` | drop lines touching these ports |
| `standard_ports` | — | dst ports treated as "normal" (anything else is flagged) |
| `weird_tlds` | — | TLDs flagged suspicious in WAN DNS queries |
| `cron` | `state_file` | optional path to stash the latest digest |

## Pitfalls

- **UDP, not TCP**: an unbound/dropped receiver loses packets with no error.
  Always confirm the bind with `ss -uln` before concluding "no logs".
- **Only one receiver per port**: `receiver.py` and `digest.py` both bind the
  same UDP port. Don't run them at once, or the digest will fail to bind.
- **Volume**: `Host is down` spam can be thousands of lines/second — it's
  filtered by default; tune `exclude` to taste.
