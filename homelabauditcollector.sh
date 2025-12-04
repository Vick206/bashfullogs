#!/usr/bin/env bash
# VERSION: 2024.12.04
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

# Path to this script, for self integrity checks and self update
SCRIPT_PATH="$(readlink -f "$0")"

# URL of the canonical collector script (raw GitHub URL)
# Override with COLLECTOR_URL env var if you like.
COLLECTOR_URL="${COLLECTOR_URL:-https://raw.githubusercontent.com/Vick206/bashfullogs/refs/heads/main/homelabauditcollector.sh}"

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

# Collects container info if it exists
collect_docker_info() {
  if ! command -v docker >/dev/null 2>&1; then
    # No docker here, skip
    return
  fi

  section "DOCKER CONTAINERS"

  echo "Docker version:"
  docker version --format '{{.Server.Version}}' 2>/dev/null || docker --version || echo "docker version unavailable"

  echo
  echo "Running containers:"
  docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.CreatedAt}}' 2>/dev/null \
    || echo "docker ps failed"

  echo
  echo "Recent container logs (last 24h, last 100 lines per container):"

  # Adjust this if you want more/less time
  local SINCE_TS
  SINCE_TS="$(date -d '24 hours ago' --iso-8601=seconds 2>/dev/null || date -d '24 hours ago' '+%Y-%m-%dT%H:%M:%S')"

  # If you want to limit which containers get audited, you can:
  #   docker ps --filter "label=homelab_audit=1" ...
  docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r cid cname; do
    [ -n "$cid" ] || continue
    echo
    echo "-- logs for ${cname} (${cid}) --"
    # Use --since to keep volume sane, then tail for last 100 lines
    if ! docker logs --since "$SINCE_TS" "$cid" 2>&1 | tail -n 100; then
      echo "  (failed to read logs for $cname)"
    fi
  done
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
# Return 0 if this system appears to be a virtual machine, 1 otherwise
is_virtualized() {
  # Prefer systemd-detect-virt if available
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    if systemd-detect-virt --quiet; then
      return 0
    else
      return 1
    fi
  fi

  # Fallback heuristics for non systemd systems

  # Check CPU flags for hypervisor
  if grep -qi 'hypervisor' /proc/cpuinfo 2>/dev/null; then
    return 0
  fi

  # Check DMI product name for common virtualization vendors
  if [ -r /sys/class/dmi/id/product_name ]; then
    if grep -qiE 'Virtual|KVM|VMware|Hyper-V|QEMU|Bochs' /sys/class/dmi/id/product_name 2>/dev/null; then
      return 0
    fi
  fi

  return 1
}

# Collect storage related health (ZFS, btrfs, SMART)
collect_storage_health() {
  section "STORAGE HEALTH"

  # ZFS status if zpool is available
  if command -v zpool >/dev/null 2>&1; then
    # Check if any pools are configured
    if zpool list -H 2>/dev/null | grep -q .; then
      echo "ZFS pool health (zpool status -x):"
      # -x gives a compact "only if unhealthy" style summary
      zpool status -x 2>/dev/null || echo "zpool status -x failed"
    else
      echo "ZFS tools installed, but no ZFS pools configured (zpool list is empty)"
    fi
  else
    echo "ZFS not detected"
  fi
}

  # btrfs filesystem usage for root, if the tooling exists
  if command -v btrfs >/dev/null 2>&1; then
    echo
    echo "Btrfs filesystem usage:"
    btrfs filesystem usage / 2>/dev/null || echo "btrfs usage failed or not btrfs"
  fi

  # SMART health if smartctl is available and this is not a virtual machine
  if command -v smartctl >/dev/null 2>&1; then
    echo
    if is_virtualized; then
      echo "SMART checks skipped: virtual machine detected (disks are virtual, check hypervisor instead)"
    else
      echo "SMART overall health (physical disks):"
      # Quick pass over common device naming patterns: sdX and nvmeXn1
      for disk in /dev/sd? /dev/nvme?n1; do
        [ -e "$disk" ] || continue
        echo
        echo "Device: $disk"
        # Only overall health summary (-H), indent output for readability
        smartctl -H "$disk" 2>/dev/null | sed 's/^/  /'
      done
    fi
  else
    echo
    echo "SMART tools not installed (smartmontools missing)"
  fi


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
# Check GitHub for a newer collector version and self update if needed.
# Comparison is based on line 2 of this script and the remote script.
self_update_if_needed() {
  # If no URL is set, nothing to do
  if [ -z "${COLLECTOR_URL:-}" ]; then
    return 0
  fi

  # Need curl or wget
  local fetch_cmd
  if command -v curl >/dev/null 2>&1; then
    fetch_cmd="curl -fsSL"
  elif command -v wget >/dev/null 2>&1; then
    fetch_cmd="wget -qO-"
  else
    echo "[collector] No curl or wget available; skipping self update check."
    return 0
  fi

  # Fetch remote script to temp
  local tmp_remote
  tmp_remote="$(mktemp "/tmp/${HOSTNAME}-collector-remote.XXXXXX")" || return 0

  if ! eval "$fetch_cmd \"$COLLECTOR_URL\"" >"$tmp_remote" 2>/dev/null; then
    echo "[collector] Failed to fetch remote collector; skipping self update."
    rm -f "$tmp_remote"
    return 0
  fi

  # Extract version from line 2 (numbers and dots)
  local local_ver remote_ver
  local_ver="$(sed -n '2p' "$SCRIPT_PATH" 2>/dev/null | sed -E 's/[^0-9.]*([0-9.]+).*/\1/')"
  remote_ver="$(sed -n '2p' "$tmp_remote" 2>/dev/null | sed -E 's/[^0-9.]*([0-9.]+).*/\1/')"

  if [ -z "$local_ver" ] || [ -z "$remote_ver" ]; then
    # Nothing sane to compare
    rm -f "$tmp_remote"
    return 0
  fi

  if [ "$local_ver" = "$remote_ver" ]; then
    # Already up to date
    rm -f "$tmp_remote"
    return 0
  fi

  # Check if remote_ver > local_ver using version sort
  if printf '%s\n%s\n' "$local_ver" "$remote_ver" | sort -V | tail -n1 | grep -qx "$remote_ver"; then
    echo "[collector] New collector version detected (local $local_ver, remote $remote_ver). Updating..."
    # Best effort backup
    cp "$SCRIPT_PATH" "${SCRIPT_PATH}.bak" 2>/dev/null || true
    if cat "$tmp_remote" >"$SCRIPT_PATH"; then
      chmod +x "$SCRIPT_PATH" 2>/dev/null || true
      rm -f "$tmp_remote"
      echo "[collector] Collector updated, reexecuting new version..."
      exec "$SCRIPT_PATH" "$@"
    else
      echo "[collector] WARNING: failed to replace collector script; keeping existing version."
    fi
  else
    # Remote is not newer
    rm -f "$tmp_remote"
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