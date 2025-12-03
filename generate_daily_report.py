#!/usr/bin/env bash
# homelab_audit_collect.sh
# Collector script for Debian-based hosts
# - Gathers health/config info
# - Ensures SSH key exists
# - Registers key on auditor via password (POC)
# - Uploads log to auditor via scp

# Exit on:
#  - any non-zero status (set -e)
#  - use of unset variables (set -u)
#  - failure in any part of a pipeline (set -o pipefail)
set -euo pipefail

# ===== SAFETY / PRIVILEGE CHECK =====

# This script modifies /var/lib, installs packages, and edits crontab.
# It must be run as root.
if [ "$(id -u)" -ne 0 ]; then
  echo "[collector] ERROR: this script must be run as root." >&2
  exit 1
fi

# ===== CONFIG =====

# IP or hostname of the central auditor box that receives reports
AUDITOR_HOST="10.0.0.242"

# Remote user on the auditor that owns the report directory
AUDITOR_USER="auditupload"

# Directory on the auditor where reports are stored
AUDITOR_DIR="/opt/homelab-audit/reports"

# POC: password for auditupload on the auditor host
# You can also export AUDITOR_PASS in the environment instead of hardcoding.
# If AUDITOR_PASS is not set, it defaults to "auditupload"
AUDITOR_PASS="${AUDITOR_PASS:-auditupload}"

# Local hostname used both in report content and remote filename
HOSTNAME="$(hostname)"

# Current date in YYYY-MM-DD format, also baked into the report file name
DATE_STR="$(date +%F)"

# Path to this script, for self integrity checks
SCRIPT_PATH="$(readlink -f "$0")"

# State directory for persistent data (hash, package snapshot, cron stamp, etc.)
STATE_DIR="/var/lib/homelab-audit"
mkdir -p "$STATE_DIR"

# File that stores the previous collector script hash
SCRIPT_HASH_FILE="${STATE_DIR}/collector.sha256"

# File that stores the last dpkg -l snapshot for diffing package changes
PKG_SNAPSHOT_FILE="${STATE_DIR}/dpkg-list.txt"

# File that marks that cron has already been configured
CRON_STAMP_FILE="${STATE_DIR}/cron_configured"

# Temporary file where this run's report is assembled before upload
TMPFILE="$(mktemp "/tmp/${HOSTNAME}-audit-${DATE_STR}.XXXXXX")"

cleanup() {
  rm -f "$TMPFILE"
}
trap cleanup EXIT

# ===== FUNCTIONS =====

# Simple helper to print a section header in the report
section() {
  echo
  echo "==== $1 ===="
}

# Collect basic host info and OS details
collect_host_info() {
  section "HOST INFO"
  echo "Hostname: $HOSTNAME"
  echo "Date: $(date --iso-8601=seconds)"
  # Prefer lsb_release if available
  if command -v lsb_release >/dev/null 2>&1; then
    echo "OS: $(lsb_release -ds)"
  # Fallback to /etc/os-release if lsb_release is missing
  elif [ -f /etc/os-release ]; then
    echo "OS: $(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
  else
    echo "OS: unknown"
  fi
  echo "Kernel: $(uname -r)"
  echo "Uptime: $(uptime -p)"
}

# Collect basic system health signals (load, disk usage, memory hogs)
collect_basic_health() {
  section "BASIC HEALTH"
  # Load averages from /proc/loadavg
  echo "Load average: $(cut -d ' ' -f1-3 /proc/loadavg)"
  echo
  echo "Disk usage (df -h / /home /var 2>/dev/null):"
  # Try focusing on common mounts, fall back to all filesystems if that fails
  df -h / /home /var 2>/dev/null || df -h
  echo
  echo "Top 5 memory consumers:"
  # ps aux sorted by memory usage, top 5 (plus header)
  ps aux --sort=-%mem | head -n 6
}

# Collect storage related health (ZFS, btrfs, SMART)
collect_storage_health() {
  section "STORAGE HEALTH"

  # ZFS status if zpool is available
  if command -v zpool >/dev/null 2>&1; then
    echo "ZFS zpool status:"
    zpool status || echo "zpool status failed"
  else
    echo "ZFS not detected"
  fi

  # btrfs filesystem usage for root, if the tooling exists
  if command -v btrfs >/dev/null 2>&1; then
    echo
    echo "Btrfs filesystem usage:"
    btrfs filesystem usage / 2>/dev/null || echo "btrfs usage failed or not btrfs"
  fi

  # SMART health if smartctl is available
  if command -v smartctl >/dev/null 2>&1; then
    echo
    echo "SMART overall health:"
    # Quick pass over common device naming patterns: sdX and nvmeXn1
    for disk in /dev/sd? /dev/nvme?n1; do
      [ -e "$disk" ] || continue
      echo
      echo "Device: $disk"
      # Only overall health summary (-H), indent output for readability
      smartctl -H "$disk" 2>/dev/null | sed 's/^/  /'
    done
  else
    echo
    echo "SMART tools not installed (smartmontools missing)"
  fi
}

# Collect basic network and security posture
collect_network_security() {
  section "NETWORK AND SECURITY"

  # Current listening sockets; prefer ss, fall back to netstat, then give up
  echo "Listening ports (ss -tulpn):"
  ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "No ss or netstat available"

  echo
  # Firewall summary: prefer ufw, then iptables-save, else nothing detected
  if command -v ufw >/dev/null 2>&1; then
    echo "UFW status:"
    ufw status verbose || echo "ufw status failed"
  elif command -v iptables-save >/dev/null 2>&1; then
    echo "iptables rules (summary):"
    iptables-save | head -n 80
  else
    echo "No firewall tooling detected (no ufw or iptables-save)"
  fi

  echo
  # List users with "real" shells (bash, zsh, fish, sh)
  echo "Users with shell accounts:"
  awk -F: '$7 ~ /(bash|zsh|fish|sh)$/ {print $1 ":" $7}' /etc/passwd
}

# Collect recent package activity and detect dpkg changes
collect_recent_changes() {
  section "PACKAGE CHANGES LAST 24H"
  if [ -f /var/log/apt/history.log ]; then
    awk -v since="$(date -d '24 hours ago' +%s)" '
      /^Start-Date:/ {
        # $2 = YYYY-MM-DD, $3 = HH:MM:SS
        date_str = $2 " " $3
        cmd = "date -d \"" date_str "\" +%s"
        t = ""
        cmd | getline t
        close(cmd)
        if (t >= since) {
          print_block = 1
        } else {
          print_block = 0
        }
      }
      print_block { print }
    ' /var/log/apt/history.log || echo "Failed to parse apt history"
  else
    echo "No /var/log/apt/history.log found"
  fi

  echo
  section "PACKAGE SNAPSHOT DELTA"
  CURRENT_SNAPSHOT="$(mktemp)"
  dpkg -l > "$CURRENT_SNAPSHOT" 2>/dev/null || echo "dpkg -l failed"
  if [ -f "$PKG_SNAPSHOT_FILE" ]; then
    echo "Changes since last snapshot:"
    diff -u "$PKG_SNAPSHOT_FILE" "$CURRENT_SNAPSHOT" || true
  else
    echo "No previous snapshot, storing baseline"
  fi
  mv "$CURRENT_SNAPSHOT" "$PKG_SNAPSHOT_FILE"
}

# Check whether the collector script has changed since the last run
collector_integrity() {
  section "COLLECTOR SCRIPT INTEGRITY"

  # If sha256sum isn't available, skip integrity checking
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum not found, skipping integrity check"
    return
  fi

  # Compute current script hash
  CURRENT_HASH="$(sha256sum "$SCRIPT_PATH" | awk '{print $1}')"

  # Compare against previous hash if present
  if [ -f "$SCRIPT_HASH_FILE" ]; then
    PREV_HASH="$(cat "$SCRIPT_HASH_FILE" 2>/dev/null || echo '')"
    if [ "$CURRENT_HASH" != "$PREV_HASH" ]; then
      echo "Collector script hash CHANGED"
      echo "Previous: $PREV_HASH"
      echo "Current : $CURRENT_HASH"
    else
      echo "Collector script hash unchanged"
    fi
  else
    # First run: no prior hash recorded
    echo "No previous hash, storing baseline"
  fi

  # Store current hash for next comparison
  echo "$CURRENT_HASH" > "$SCRIPT_HASH_FILE"
}

# Collect high priority log entries from the last 24 hours
collect_logs() {
  section "RECENT SYSTEM ERRORS"

  # Use journalctl if available, otherwise state that logs are unavailable
  if command -v journalctl >/dev/null 2>&1; then
    # Priority -p 3 = errors, -S sets since, -n limits count
    journalctl -p 3 -S "24 hours ago" -n 100 2>/dev/null || echo "journalctl failed"
  else
    echo "journalctl not present"
  fi
}

# ===== SSH KEY POC BOOTSTRAP =====

# Ensure a local SSH key exists and is registered on the auditor for key-based auth
ensure_ssh_key_and_register() {
  # Use the invoking user's home directory for SSH key storage
  local SSH_DIR="$HOME/.ssh"
  local PRIVKEY="$SSH_DIR/id_ed25519"
  local PUBKEY="$SSH_DIR/id_ed25519.pub"

  mkdir -p "$SSH_DIR"
  chmod 700 "$SSH_DIR"

  # create keypair if missing
  if [ ! -f "$PUBKEY" ]; then
    echo "[collector] No SSH key found, generating one..."
    ssh-keygen -t ed25519 -f "$PRIVKEY" -N "" -q
  fi

  # If sshpass is missing, try to install it with apt and keep going either way
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[collector] sshpass not found, installing..."
    apt-get update -y >/dev/null 2>&1 && apt-get install -y sshpass >/dev/null 2>&1 \
      || echo "[collector] WARNING: failed to install sshpass"
  fi

  # verify it exists now, otherwise skip key registration
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[collector] sshpass still missing. Skipping key registration."
    return
  fi

  # Warn if the password is obviously default/placeholder
  if [ -z "$AUDITOR_PASS" ] || [ "$AUDITOR_PASS" = "changeme" ]; then
    echo "[collector] WARNING: AUDITOR_PASS not set or still 'changeme'; key registration may fail."
  fi

  echo "[collector] Ensuring our key is registered on auditor (POC mode)..."
  # Use password auth once to ensure our key is in authorized_keys
  # We avoid duplicating entries by checking grep first.
  sshpass -p "$AUDITOR_PASS" ssh -o StrictHostKeyChecking=accept-new \
    "${AUDITOR_USER}@${AUDITOR_HOST}" \
    "mkdir -p /home/${AUDITOR_USER}/.ssh && \
     touch /home/${AUDITOR_USER}/.ssh/authorized_keys && \
     chmod 700 /home/${AUDITOR_USER}/.ssh && \
     chmod 600 /home/${AUDITOR_USER}/.ssh/authorized_keys && \
     chown -R ${AUDITOR_USER}:${AUDITOR_USER} /home/${AUDITOR_USER}/.ssh && \
     grep -qx \"$(cat "$PUBKEY")\" /home/${AUDITOR_USER}/.ssh/authorized_keys || \
     echo \"$(cat "$PUBKEY")\" >> /home/${AUDITOR_USER}/.ssh/authorized_keys" \
    || echo "[collector] WARNING: failed to register key on auditor (POC)"
}

# Upload the assembled report to the auditor via scp, preferring key auth
upload_report() {
  # Remote filename includes hostname and date for easy grouping
  local REMOTE_NAME="${HOSTNAME}-${DATE_STR}.log"

  # First try key-based scp
  if scp -q "$TMPFILE" "${AUDITOR_USER}@${AUDITOR_HOST}:${AUDITOR_DIR}/${REMOTE_NAME}" 2>/dev/null; then
    echo "[collector] Report uploaded via key auth."
    return 0
  fi

  echo "[collector] Key auth failed, trying password (POC)..."

  # If sshpass is missing here, password fallback cannot work
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[collector] ERROR: sshpass not installed; cannot fall back to password upload."
    return 1
  fi

  # Password-based scp as a last resort, with host key auto-accept
  if sshpass -p "$AUDITOR_PASS" scp -o StrictHostKeyChecking=accept-new -q \
      "$TMPFILE" "${AUDITOR_USER}@${AUDITOR_HOST}:${AUDITOR_DIR}/${REMOTE_NAME}"; then
    echo "[collector] Report uploaded via password (POC)."
    return 0
  else
    echo "[collector] ERROR: failed to upload report to auditor"
    return 1
  fi
}

# Inject a crontab entry to run this script at midnight and noon
add_cronjob() {
  # Resolve the script path so cron always calls the absolute path
  local SCRIPT_PATH_CRON
  SCRIPT_PATH_CRON="$(readlink -f "$0")"

  # Cron line: minute hour day-of-month month day-of-week command
  # Here: minute 0, hours 0 and 12, every day
  local CRONLINE="0 0,12 * * * $SCRIPT_PATH_CRON"

  # If cron already contains this line, don't be a pest
  if crontab -l 2>/dev/null | grep -Fq "$SCRIPT_PATH_CRON"; then
    echo "[collector] Cron job already present in crontab."
    return 0
  fi

  echo "[collector] Adding cron job to run at midnight and noon..."
  # Append our line to existing crontab (or start a new one if none)
  if (crontab -l 2>/dev/null; echo "$CRONLINE") | crontab -; then
    echo "[collector] Cron job added."
    return 0
  else
    echo "[collector] ERROR: failed to install cron job."
    return 1
  fi
}

# ===== MAIN =====

# Flag to control whether we auto-add a cron job for this script
NO_CRON=0
# Simple manual argument parsing: if any arg is --no-cron, disable cron setup
for arg in "$@"; do
  [ "$arg" = "--no-cron" ] && NO_CRON=1
done

# Run all collectors and write output to the temporary report file
{
  collect_host_info
  collect_basic_health
  collect_storage_health
  collect_network_security
  collect_recent_changes
  collector_integrity
  collect_logs
} > "$TMPFILE"

# Ensure key exists and is registered (POC) before upload
ensure_ssh_key_and_register

# Ship to auditor, but do not let failure kill the whole script via set -e
UPLOAD_OK=0
if upload_report; then
  UPLOAD_OK=1
else
  UPLOAD_OK=0
fi

# Only set up cron when:
#  - user did not disable it with --no-cron
#  - upload succeeded (so we know at least one good run worked)
#  - we have not already recorded cron as configured
if [ "$NO_CRON" -eq 0 ] && [ "$UPLOAD_OK" -eq 1 ]; then
  if [ ! -f "$CRON_STAMP_FILE" ]; then
    if add_cronjob; then
      touch "$CRON_STAMP_FILE"
    else
      echo "[collector] WARNING: cron setup failed; will retry on next successful run."
    fi
  else
    # Stamp exists, don't spam crontab every time
    echo "[collector] Cron already configured (stamp present)."
  fi
elif [ "$NO_CRON" -eq 0 ] && [ "$UPLOAD_OK" -eq 0 ]; then
  echo "[collector] Skipping cron setup because upload failed."
fi

root@VXAI:/opt/homelab-audit# ca          
caller     capsh      captoinfo  case       cat        catman
root@VXAI:/opt/homelab-audit# cat  
.git/                     homelabauditcollector.sh
README.md                 mkauditusr.sh
__pycache__/              reports/
generate_daily_report.py  venv/
root@VXAI:/opt/homelab-audit# cat generate_daily_report.py 
#!/usr/bin/env python3
import os
import glob
import datetime
import requests
import textwrap
import smtplib
from email.mime.text import MIMEText

# ===== CONFIG =====
REPORT_DIR = "/opt/homelab-audit/reports"
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")

# Gmail settings
EMAIL_FROM = os.environ.get("GMAIL_FROM", "GMAILACCOUNT")  # must be your Gmail
EMAIL_TO = [os.environ.get("GMAIL_TO", EMAIL_FROM)]         # default: send to self

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("GMAIL_SMTP_USER", EMAIL_FROM)   # usually same as FROM
SMTP_PASS = os.environ.get("GMAIL_APP_PASSWORD", "lolno :D")            # 16-char app password


# ===== HELPERS =====

def load_reports_for_today():
  today = datetime.date.today().strftime("%Y-%m-%d")
  pattern = os.path.join(REPORT_DIR, f"*-{today}.log")
  files = sorted(glob.glob(pattern))
  reports = []
  for path in files:
    try:
      with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
      hostname = os.path.basename(path).split("-")[0]
      reports.append((hostname, content))
    except Exception as e:
      print(f"Failed to read {path}: {e}")
  return reports

def build_prompt(reports):
  today = datetime.date.today().isoformat()
  header = textwrap.dedent(f"""
    You are an SRE and systems auditor for a small homelab.

    You are given daily audit logs from multiple hosts. Each host log contains
    sections like HOST INFO, BASIC HEALTH, STORAGE HEALTH, NETWORK AND SECURITY,
    PACKAGE CHANGES, COLLECTOR SCRIPT INTEGRITY, and RECENT SYSTEM ERRORS.

    Tasks:

    1. Give a short overall summary of health and risk in at most 8 lines.
    2. For each host:
       - List any problems with a severity from 1 to 10.
       - Explain clearly what looks wrong
         (for example failing SMART, degraded pool, very open firewall,
         repeated log errors, package changes that look risky).
       - Suggest concrete remediation in plain language,
         but do not give shell commands.
       - If a host shows a clear gap in telemetry
         (for example SMART not installed or missing firewall config)
         mention what is missing so the admin can fix it.

    Be concise and practical. Assume the reader is comfortable with Linux,
    but wants prioritised guidance.

    Today is {today}.

    Here are the host logs:
  """).strip()

  body_parts = []
  for hostname, content in reports:
    body_parts.append(f"\n\n===== HOST: {hostname} =====\n{content}")

  return header + "".join(body_parts)

def call_ollama(prompt: str) -> str:
  payload = {
    "model": MODEL,
    "prompt": prompt,
    "stream": False,
  }
  resp = requests.post(OLLAMA_URL, json=payload, timeout=600)
  resp.raise_for_status()
  data = resp.json()
  return data.get("response", "").strip()

def send_email(subject: str, body: str):
  if not SMTP_PASS:
    raise RuntimeError("GMAIL_APP_PASSWORD (SMTP_PASS) is not set")

  msg = MIMEText(body, "plain", "utf-8")
  msg["Subject"] = subject
  msg["From"] = EMAIL_FROM
  msg["To"] = ", ".join(EMAIL_TO)

  with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
    s.ehlo()
    s.starttls()
    s.ehlo()
    s.login(SMTP_USER, SMTP_PASS)
    s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

def main():
  reports = load_reports_for_today()
  if not reports:
    print("No reports for today, nothing to do.")
    return

  prompt = build_prompt(reports)
  try:
    result = call_ollama(prompt)
  except Exception as e:
    print(f"LLM call failed: {e}")
    return

  subject = f"Homelab daily audit report {datetime.date.today().isoformat()}"
  try:
    send_email(subject, result)
    print("Report email sent.")
  except Exception as e:
    print(f"Failed to send email: {e}")

if __name__ == "__main__":
  main(