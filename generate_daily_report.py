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
SUMMARY_DIR = "/opt/homelab-audit/summaries"

MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")

# Per-host report trimming for potato hardware (characters)
MAX_REPORT_CHARS = int(os.environ.get("MAX_REPORT_CHARS", "4000"))

# Gmail settings
EMAIL_FROM = os.environ.get("GMAIL_FROM", "hochkbry@gmail.com")  # must be your Gmail
EMAIL_TO = [os.environ.get("GMAIL_TO", EMAIL_FROM)]        # default: send to self

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("GMAIL_SMTP_USER", EMAIL_FROM)  # usually same as FROM
SMTP_PASS = os.environ.get("GMAIL_APP_PASSWORD", "tizbbkapjibefuhd")  # 16-char app password

os.makedirs(SUMMARY_DIR, exist_ok=True)


# ===== HELPERS =====

def load_reports_for_today():
    """Return list of (hostname, content) for today's reports."""
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


def trim_report(content: str) -> str:
    """Hard cap report size to avoid feeding novels to the LLM."""
    if len(content) <= MAX_REPORT_CHARS:
        return content
    return content[:MAX_REPORT_CHARS] + "\n\n[Report truncated for summarisation]\n"


def build_host_prompt(hostname: str, content: str) -> str:
    today = datetime.date.today().isoformat()
    header = textwrap.dedent(f"""
        You are an SRE and systems auditor for a small homelab.

        You are given the daily audit log for a SINGLE host: {hostname}.
        The log has sections like:
        - HOST INFO
        - BASIC HEALTH
        - STORAGE HEALTH
        - NETWORK AND SECURITY
        - PACKAGE CHANGES
        - COLLECTOR SCRIPT INTEGRITY
        - RECENT SYSTEM ERRORS

        Tasks for THIS ONE HOST:

        1. Give a short 3–5 line summary of this host's overall health and risk.
        2. List any problems with a severity from 1 to 10 (10 = worst).
        3. Explain clearly what looks wrong
           (for example failing SMART, degraded pool, very open firewall,
           repeated log errors, risky package changes).
        4. Suggest concrete remediation in plain language,
           but do NOT give shell commands.
        5. If there is a clear gap in telemetry
           (e.g. SMART not installed or missing firewall config)
           mention what is missing so the admin can fix it.

        Be concise and practical. Assume the reader is comfortable with Linux.

        Today is {today}.

        Here is the raw log for host {hostname}:
    """).strip()

    return header + "\n\n" + trim_report(content)


def build_global_prompt(host_summaries):
    """
    host_summaries: list of (hostname, summary_text)
    """
    today = datetime.date.today().isoformat()
    header = textwrap.dedent(f"""
        You are an SRE and systems auditor for a small homelab.

        You are given pre-computed per-host summaries from multiple machines.
        Each summary already describes that host's health, issues, severity and
        suggested remediation.

        Tasks:

        1. Give an overall summary of homelab health and risk in at most 8 lines.
           Focus on what needs attention soon.
        2. Identify the top 5 most important problems across ALL hosts,
           sorted by urgency and impact.
        3. Group issues by theme when possible (e.g. storage, network,
           security, telemetry gaps).
        4. Suggest high-level remediation priorities for the next 24–72 hours.
           Keep it practical and concise; no shell commands.

        Today is {today}.

        Here are the per-host summaries:
    """).strip()

    body_parts = []
    for hostname, summary in host_summaries:
        body_parts.append(f"\n\n===== HOST SUMMARY: {hostname} =====\n{summary}")

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


def summary_path_for(hostname: str, date_str: str) -> str:
    return os.path.join(SUMMARY_DIR, f"{hostname}-{date_str}.summary.txt")


def load_or_generate_host_summaries(reports):
    """
    For each (hostname, content) in reports:
    - if today's summary file exists, load it
    - otherwise call the LLM to generate it and save to disk

    Returns list of (hostname, summary_text).
    """
    date_str = datetime.date.today().strftime("%Y-%m-%d")
    host_summaries = []

    for hostname, content in reports:
        path = summary_path_for(hostname, date_str)
        summary_text = None

        # Reuse cached summary if present
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    summary_text = f.read().strip()
                print(f"Loaded cached summary for {hostname}")
            except Exception as e:
                print(f"Failed to read cached summary for {hostname}: {e}")

        if not summary_text:
            print(f"Generating summary for host {hostname}...")
            host_prompt = build_host_prompt(hostname, content)
            try:
                summary_text = call_ollama(host_prompt)
            except Exception as e:
                print(f"LLM call failed for host {hostname}: {e}")
                # Store a stub so the global summary still has something
                summary_text = f"Failed to generate summary for {hostname}: {e}"

            # Write summary to disk for reuse
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(summary_text)
            except Exception as e:
                print(f"Failed to write summary for {hostname}: {e}")

        host_summaries.append((hostname, summary_text))

    return host_summaries


def main():
    reports = load_reports_for_today()
    if not reports:
        print("No reports for today, nothing to do.")
        return

    # First pass: per-host summaries
    host_summaries = load_or_generate_host_summaries(reports)

    # Second pass: global summary across hosts
    global_prompt = build_global_prompt(host_summaries)
    try:
        global_summary = call_ollama(global_prompt)
    except Exception as e:
        print(f"LLM call failed for global summary: {e}")
        return

    # Build email body: global view + per-host details
    body_parts = [
        "=== Homelab daily audit summary ===\n",
        global_summary,
        "\n\n=== Per-host summaries ===\n",
    ]
    for hostname, summary in host_summaries:
        body_parts.append(f"\n----- {hostname} -----\n{summary}\n")

    email_body = "".join(body_parts)
    subject = f"Homelab daily audit report {datetime.date.today().isoformat()}"

    try:
        send_email(subject, email_body)
        print("Report email sent.")
    except Exception as e:
        print(f"Failed to send email: {e}")


if __name__ == "__main__":
    main()
