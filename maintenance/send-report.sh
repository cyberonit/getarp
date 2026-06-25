#!/usr/bin/env bash
# Monthly dependency report — runs check-updates.sh and emails the output.
# Called by cron; can also be run manually to test email delivery.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TO="stefan.ionita@gmail.com"
SUBJECT="[getarp] Monthly dependency report — $(date '+%B %Y')"
LOG="${ROOT}/maintenance/logs/updates-$(date +%Y-%m).log"

mkdir -p "$(dirname "$LOG")"

# Run the check and capture output to log
bash "${ROOT}/maintenance/check-updates.sh" > "$LOG" 2>&1

# Send the log as email body
{
    printf "To: %s\n" "$TO"
    printf "Subject: %s\n" "$SUBJECT"
    printf "Content-Type: text/plain; charset=utf-8\n"
    printf "\n"
    cat "$LOG"
} | msmtp "$TO"
