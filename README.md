# bashfullogs

A stupid simple distributed log collector plus local LLM powered report generator.  
Runs on Debian based Linux systems. Tested on **Ubuntu**, **Raspberry Pi OS**, and other Debian derivatives. Still held together with the usual layers of excuses.

---

## What it does

1. **Collectors** run on each Linux host:
   - Grab system logs and basic health data
   - Ensure SSH keys exist
   - Ship logs to a central **auditor** box via SCP

2. **Auditor** receives those logs, feeds them into a **local LLM**, and produces a readable summary report (email for now)

It’s basically a homelab SIEM that refuses to take itself seriously.

---

## Current Status

Working features:

- Collector script for Debian based hosts
- Auditor user provisioning
- Python report generator talking to a local model (Ollama tested)
- Daily scheduled execution via cron

**WIP:**

- PowerShell based Windows log aggregator
- Removing hardcoded credentials in favor of arguments, environment variables, or config files
- Breaking collector scripts into functions to reduce code duplication

Expect breakage if you look at this sideways.
