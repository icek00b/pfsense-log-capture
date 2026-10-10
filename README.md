# pfSense Log Capture — Hermes Skill

A [Hermes Agent](https://hermes-agent.nousresearch.com/docs) skill for capturing
and summarizing **pfSense firewall syslog**. pfSense *pushes* syslog over UDP to
a receiver — there is no pull API — so "get the pfSense logs" means "run the
receiver and let packets land."

This skill ships two stdlib Python tools, a `config.yaml` for timings and
include/exclude filters, and a ready-to-load **cron job** that turns each capture
into a short WAN security digest delivered over your platform.

```
pfsense-log-capture/
├── SKILL.md              # Hermes skill definition (triggers, workflow, pitfalls)
├── README.md             # you are here
├── config.yaml           # timings + include/exclude filters (scrubbed for your LAN)
├── receiver.py           # continuous UDP syslog listener -> rotating log file
├── digest.py             # ephemeral per-run WAN security digest (the cron script)
├── common.py             # shared config loader
├── cron.example.json     # scrubbed Hermes cron job definition
├── cron.example.sh       # plain crontab wrapper (no scheduler needed)
├── requirements.txt      # PyYAML
└── .gitignore
```

## Install as a Hermes skill

Drop the directory into your Hermes skills folder and it becomes discoverable:

```bash
git clone git@github.com:<you>/pfsense-log-capture.git \
  ~/.hermes/skills/devops/pfsense-log-capture
pip install -r ~/.hermes/skills/devops/pfsense-log-capture/requirements.txt
```

Edit `config.yaml` for your LAN (bind port, interface names, exclude lists —
see below). Then load the cron job (see [Cron job](#cron-job)).

## When the agent uses it

The skill activates for requests like *"get pfSense logs"*, *"what's hitting my
firewall"*, *"pfSense WAN digest / IDS alerts / blocked scanners"*. Because the
pipeline is UDP-push, the agent binds the receiver first and lets packets land
rather than expecting a queryable endpoint.

## The pipeline

1. **Sender** — pfSense: **Status → System Logs → Settings → Remote syslog
   servers** → add `<this box's IP>:<listen.port>` (default `42069`).
2. **Receiver** — `receiver.py` binds the UDP port and writes everything to a
   rotating log file. Good for long-running capture.
3. **Digest** — `digest.py` (the cron script) listens for a short window, prints
   a small bounded WAN security summary, and **deletes** the raw capture before
   it exits. Nothing persists between runs.

The digest surfaces the signals that matter and drops the noise:

- Suricata IDS/IPS **alerts** (severity, signature, src→dst, proto, category)
- WAN **DNS queries**, with weird-TLD / very-long-label domains flagged
- **filterlog** block/pass counts, top blocked external scanners, top WAN dst ports
- Internal→external egress on **non-standard ports** (possible C2 / odd conns)
- Dropped by default: `sendto: Host is down` spam, MQTT/meshtastic chatter,
  LAN-interface traffic

## Cron job

`cron.example.json` is the scrubbed Hermes cron job that runs `digest.py` every
2 hours and ships the rendered digest to your platform. Each tick the script's
stdout is the **only** log data the agent reasons over — it never reads the raw
log. Load it through Hermes' scheduler, or use `cron.example.sh` for a plain
crontab entry:

```
0 */2 * * *  ~/.hermes/skills/devops/pfsense-log-capture/cron.example.sh
```

## Quick start (manual)

```bash
# continuous capture (verify the UDP bind: ss -uln | grep :42069)
python3 receiver.py
python3 receiver.py --port 5514 --only-wan

# one-shot WAN digest
python3 digest.py --seconds 60
```

## Configuration (`config.yaml`)

Every value is overridable by a matching CLI flag.

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
- **One receiver per port**: `receiver.py` and `digest.py` both bind the same UDP
  port. Don't run them simultaneously, or the digest fails to bind.
- **Volume**: `Host is down` spam can be thousands of lines/second — filtered by
  default; tune `exclude` to taste. Redirect to `--dump` and count rather than
  printing raw to the terminal.

Fill in your own
values under `config.yaml` (`exclude.src_ips`, `interface`) and in
`cron.example.json` (`deliver`).
