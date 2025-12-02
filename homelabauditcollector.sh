#!/usr/bin/env bash
# homelab_audit_collect.sh
# Collector script for Debian-based hosts
# - Gathers health/config info
# - Ensures SSH key exists
# - Registers key on auditor via password (POC)
# - Uploads log to auditor via scp

set -euo pipefail

# ===== CONFIG =====
AUDITOR_HOST="10.0.0.242"
AUDITOR_USER="auditupload"
AUDITOR_DIR="/opt/homelab-audit/reports"

# POC: password for auditupload on the auditor host
# You can also export AUDITOR_PASS in the environment instead of hardcoding.
AUDITOR_PASS="${AUDITOR_PASS:-auditupload}"

HOSTNAME="$(hostname)"
DATE_STR="$(date +%F)"
TMPFILE="$(mktemp "/tmp/${HOSTNAME}-audit-${DATE_STR}.XXXXXX")"

# Path to this script, for self integrity checks
SCRIPT_PATH="$(readlink -f "$0")"
STATE_DIR="/var/lib/homelab-audit"
mkdir -p "$STATE_DIR"
SCRIPT_HASH_FILE="${STATE_DIR}/collector.sha256"
PKG_SNAPSHOT_FILE="${STATE_DIR}/dpkg-list.txt"

# ===== FUNCTIONS =====

section() {
  echo
  echo "==== $1 ===="
}

collect_host_info() {
  section "HOST INFO"
  echo "Hostname: $HOSTNAME"
  echo "Date: $(date --iso-8601=seconds)"
  if command -v lsb_release >/dev/null 2>&1; then
    echo "OS: $(lsb_release -ds)"
  elif [ -f /etc/os-release ]; then
    echo "OS: $(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
  else
    echo "OS: unknown"
  fi
  echo "Kernel: $(uname -r)"
  echo "Uptime: $(uptime -p)"
}

collect_basic_health() {
  section "BASIC HEALTH"
  echo "Load average: $(cut -d ' ' -f1-3 /proc/loadavg)"
  echo
  echo "Disk usage (df -h / /home /var 2>/dev/null):"
  df -h / /home /var 2>/dev/null || df -h
  echo
  echo "Top 5 memory consumers:"
  ps aux --sort=-%mem | head -n 6
}

collect_storage_health() {
  section "STORAGE HEALTH"
  if command -v zpool >/dev/null 2>&1; then
    echo "ZFS zpool status:"
    zpool status || echo "zpool status failed"
  else
    echo "ZFS not detected"
  fi

  if command -v btrfs >/dev/null 2>&1; then
    echo
    echo "Btrfs filesystem usage:"
    btrfs filesystem usage / 2>/dev/null || echo "btrfs usage failed or not btrfs"
  fi

  if command -v smartctl >/dev/null 2>&1; then
    echo
    echo "SMART overall health:"
    for disk in /dev/sd? /dev/nvme?n1; do
      [ -e "$disk" ] || continue
      echo
      echo "Device: $disk"
      smartctl -H "$disk" 2>/dev/null | sed 's/^/  /'
    done
  else
    echo
    echo "SMART tools not installed (smartmontools missing)"
  fi
}

collect_network_security() {
  section "NETWORK AND SECURITY"
  echo "Listening ports (ss -tulpn):"
  ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "No ss or netstat available"

  echo
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
  echo "Users with shell accounts:"
  awk -F: '$7 ~ /(bash|zsh|fish|sh)$/ {print $1 ":" $7}' /etc/passwd
}

collect_recent_changes() {
  section "PACKAGE CHANGES LAST 24H"
  if [ -f /var/log/apt/history.log ]; then
    awk -v since="$(date -d '24 hours ago' +%s)" '
      /^Start-Date:/ {
        date = $2
        time = $3
        gsub(/-/," ",date)
        cmd = "date -d \"" date " " time "\" +%s"
        cmd | getline t
        close(cmd)
        if (t >= since) print_block=1; else print_block=0
      }
      print_block {print}
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

collector_integrity() {
  section "COLLECTOR SCRIPT INTEGRITY"
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum not found, skipping integrity check"
    return
  fi

  CURRENT_HASH="$(sha256sum "$SCRIPT_PATH" | awk '{print $1}')"

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
    echo "No previous hash, storing baseline"
  fi

  echo "$CURRENT_HASH" > "$SCRIPT_HASH_FILE"
}

collect_logs() {
  section "RECENT SYSTEM ERRORS"
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -p 3 -S "24 hours ago" -n 100 2>/dev/null || echo "journalctl failed"
  else
    echo "journalctl not present"
  fi
}

# ===== SSH KEY POC BOOTSTRAP =====
ensure_ssh_key_and_register() {
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

  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[collector] WARNING: sshpass not installed, cannot register key on auditor (POC)"
    return
  fi

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

upload_report() {
  local REMOTE_NAME="${HOSTNAME}-${DATE_STR}.log"

  # First try key-based scp
  if scp -q "$TMPFILE" "${AUDITOR_USER}@${AUDITOR_HOST}:${AUDITOR_DIR}/${REMOTE_NAME}" 2>/dev/null; then
    echo "[collector] Report uploaded via key auth."
    return 0
  fi

  echo "[collector] Key auth failed, trying password (POC)..."

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

  sshpass -p "$AUDITOR_PASS" scp -o StrictHostKeyChecking=accept-new -q \
    "$TMPFILE" "${AUDITOR_USER}@${AUDITOR_HOST}:${AUDITOR_DIR}/${REMOTE_NAME}" \
    && echo "[collector] Report uploaded via password (POC)." \
    || { echo "[collector] ERROR: failed to upload report to auditor"; return 1; }
}

# ===== MAIN =====

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

# Ship to auditor
upload_report

rm -f "$TMPFILE"

