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
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")  # whatever you use
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")

EMAIL_FROM = "homelab-reporter@example.lan"
EMAIL_TO = ["you@example.lan"]
SMTP_HOST = "localhost"
SMTP_PORT = 25

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
  msg = MIMEText(body, "plain", "utf-8")
  msg["Subject"] = subject
  msg["From"] = EMAIL_FROM
  msg["To"] = ", ".join(EMAIL_TO)

  with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
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
  main()
