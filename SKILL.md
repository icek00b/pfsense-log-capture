---
name: pfsense-log-capture
description: Capture and summarize pfSense firewall syslog over UDP; ephemeral WAN security digest for Hermes cron.
metadata:
  hermes:
    tags: [pfSense, firewall, syslog, security, IDS, suricata, cron, devops]
    related_skills: []
---

# pfSense log capture

Trigger when the user asks to "get pfSense logs", "what's hitting the firewall",
"pfSense WAN digest / IDS alerts / blocked scanners", or wants a recurring
firewall security summary. pfSense **pushes** syslog over UDP to a receiver —
there is no pull API — so "get logs" means "bind the receiver and let packets
land," never "poll an endpoint."

## Layout (this skill dir)

- `receiver.py` — continuous UDP listener → rotating log file (long-running capture).
- `digest.py` — ephemeral per-run WAN security digest; **the cron script**.
- `common.py` — config loader (reads `config.yaml` next to the scripts, or
  `$PFSENSE_LOG_CONFIG`, or an explicit `--config`).
- `config.yaml` — timings + include/exclude filters. **Scrubbed**: fill in your
  LAN values (`exclude.src_ips`, `interface`) and ports are kept as-is.
- `cron.example.json` — scrubbed Hermes cron job definition.
- `cron.example.sh` — plain crontab wrapper if you aren't on a scheduler.

## Setup (once)

1. pfSense: **Status → System Logs → Settings → Remote syslog servers** → add
   `<this box's IP>:<listen.port>` (default `42069`).
2. `pip install -r requirements.txt` (PyYAML only).
3. Edit `config.yaml` for your LAN (bind port, WAN/LAN interface names, exclude lists).

## Workflow

1. **Confirm liveness** (LAN): `ping -c2 <firewall>` and the web UI responds.
2. **Confirm the bind before concluding "no logs"**: `ss -uln | grep :<port>`.
   UDP has no connection — an unbound port silently drops packets.
3. **Capture**:
   - Continuous: `python3 receiver.py` (append to `receiver.dump`, rotates at
     `receiver.max_size`). Background it for long runs.
   - One-shot / cron: `python3 digest.py` — listens for a SHORT window, prints a
     small bounded WAN digest, deletes the raw temp before exiting. Nothing
     persists. Use `--keep-raw` + `timeout` for debugging.
4. **Recurring digest**: load `cron.example.json` (runs `digest.py` every 2h and
   delivers the report to your platform), or wire `cron.example.sh` into crontab.

## What surfaces in the digest (filter by section)

- `suricata` alert events — severity, signature, src→dst:port, proto, category.
- WAN DNS queries — unique domains; weird-TLD / very-long-label flagged.
- `filterlog` block/pass counts, top blocked external scanners, top WAN dst ports.
- Internal→external egress on non-standard ports (possible C2 / odd conns).

## Noise dropped by default (configurable under `exclude`)

- `sendto: Host is down` — pfSense's *secondary* syslog dest is unreachable; the
  primary delivery to the receive port is fine.
- MQTT/meshtastic chatter (`longfast`, MQTT ports 16720/1883/8883, configured src IPs).
- All non-WAN interface traffic (LAN `igb1`/`igb2` chatter).

## Pitfalls

- **UDP, not TCP**: a dropped/unbound receiver loses packets silently. Always
  verify the bind with `ss` first.
- **One receiver per port**: `receiver.py` and `digest.py` both bind the same UDP
  port — don't run them at once, or the digest fails to bind.
- **Volume**: `Host is down` can be thousands of lines/second. Filter for
  summaries; `only_wan` is the knob for WAN-only. Redirect to `--dump` and
  count/filter rather than printing 100k+ chars to the terminal.
- **Scrubbed defaults**: the published `config.yaml` ships `exclude.src_ips: []`
  and placeholder interfaces — set them for your environment or the digest won't
  drop your known-noisy senders.
