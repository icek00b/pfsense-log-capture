#!/usr/bin/env bash
# Example cron wrapper for the ephemeral pfSense WAN digest.
#
# Runs digest.py for one short window and emits the rendered digest. Pipe it
# wherever you want delivery (mail, webhook, XMPP bot, append to a file).
#
# crontab example — every 2 hours:
#   0 */2 * * * /path/to/pfsense-log-capture/cron.example.sh
#
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DIGEST="$(python3 "$DIR/digest.py" --seconds 30)"

# Drop a "no data" cycle quietly if you don't want empty pages:
if echo "$DIGEST" | grep -q "no logs received"; then
  exit 0
fi

# --- delivery: pick ONE ---
echo "$DIGEST" | mail -s "pfSense WAN digest $(date +%F\ %H:%M)" you@example.com
# echo "$DIGEST" | curl -fsS -X POST --data-binary @- https://hooks.example.com/pfsense
# printf '%s\n' "$DIGEST" >> /var/log/pfsense-digest.log
