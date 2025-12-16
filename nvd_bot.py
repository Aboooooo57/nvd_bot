import re

import requests
import telebot
import schedule
import time
import json
import os
import html
from datetime import datetime, timedelta, timezone

# ================= CONFIGURATION =================
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')
NVD_API_KEY = os.getenv('NVD_API_KEY')
DATA_FILE = 'data/seen_cves.json'

# 🚨 EDIT THIS LIST: Case-insensitive keywords to watch for
WATCHLIST = [
    # --- Web Stack (Your previous list) ---
    "fastapi", "next.js", "nextjs", "react", "python", "typescript",

    # --- Linux Core ---
    "linux kernel",  # Best for catching kernel specific issues
    "kernel",  # Broader, but might catch non-Linux kernels (rare in NVD)

    # --- Linux Distributions (Distros) ---
    "ubuntu",
    "debian",
    "redhat", "rhel",
    "fedora",
    "centos",
    "suse",
    "arch linux",

    # --- Specific Kernel Subsystems (High Risk Areas) ---
    "netfilter",  # Firewall / Packet filtering
    "bpf", "ebpf",  # Berkeley Packet Filter (common attack vector)
    "kvm",  # Virtualization
    "bluetooth",  # Wireless drivers
    "wifi", "wlan",  # Network drivers
    "usb",  # USB drivers
    "overlayfs",  # File system (common for privilege escalation)
    "glibc",  # Core C library
    "systemd"  # Init system
]
# =================================================

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)


def load_seen_cves():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def save_seen_cve(cve_id):
    seen_ids = load_seen_cves()
    if cve_id not in seen_ids:
        seen_ids.append(cve_id)
        if len(seen_ids) > 1000:
            seen_ids = seen_ids[-1000:]
        with open(DATA_FILE, 'w') as f:
            json.dump(seen_ids, f)


def get_new_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    now = datetime.now(timezone.utc)
    last_window = now - timedelta(minutes=6)
    fmt = '%Y-%m-%dT%H:%M:%S.000'
    pub_end_date = now.strftime(fmt)
    pub_start_date = last_window.strftime(fmt)

    params = {
        'pubStartDate': pub_start_date,
        'pubEndDate': pub_end_date,
        'resultsPerPage': 100
    }

    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY

    try:
        print(f"Checking NVD between {pub_start_date} and {pub_end_date}...")
        response = requests.get(url, params=params, headers=headers, timeout=20)
        if response.status_code == 200:
            return response.json().get('vulnerabilities', [])
        else:
            print(f"API Error: {response.status_code}")
            return []
    except Exception as e:
        print(f"Connection Error: {e}")
        return []


def is_relevant(description):
    """
    Checks if the description contains any keyword as a WHOLE WORD.
    """
    if not description:
        return False

    desc_lower = description.lower()

    for keyword in WATCHLIST:
        # \b means "word boundary".
        # It matches "react" but NOT "reaction", "create", etc.
        pattern = r'\b' + re.escape(keyword) + r'\b'

        if re.search(pattern, desc_lower):
            # Debugging: Print what matched
            print(f"✅ Match found! Keyword: '{keyword}' found in description.")
            return True

    return False


def format_and_send(cve_item):
    cve = cve_item.get('cve', {})
    cve_id = cve.get('id')

    if not cve_id: return

    # 1. Check Duplicates
    seen_ids = load_seen_cves()
    if cve_id in seen_ids:
        print(f"Skipping duplicate: {cve_id}")
        return

    # 2. Extract Description
    raw_description = "No description."
    for desc in cve.get('descriptions', []):
        if desc.get('lang') == 'en':
            raw_description = desc.get('value')
            break

    # 3. Filter Logic (Check if relevant)
    if not is_relevant(raw_description):
        print(f"Skipping {cve_id} (Not in stack)")
        save_seen_cve(cve_id)
        return

    # 4. Format Description
    if len(raw_description) > 400:
        raw_description = raw_description[:397] + "..."

    # First, sanitize HTML special characters to prevent errors
    safe_description = html.escape(raw_description)

    # --- BOLDING LOGIC START ---
    # We sort by length (longest first) to prevent issues (e.g. matching 'next' inside 'next.js')
    sorted_keywords = sorted(WATCHLIST, key=len, reverse=True)

    for word in sorted_keywords:
        # Create a regex pattern:
        # (?i) = Case insensitive
        # \b   = Word boundary (prevents bolding 'react' inside 'creation')
        pattern = r'(?i)\b(' + re.escape(word) + r')\b'

        # Replace found word with <b>Word</b> (preserving original casing)
        safe_description = re.sub(pattern, r'<b>\1</b>', safe_description)
    # --- BOLDING LOGIC END ---

    safe_cve_id = html.escape(cve_id)

    # 5. Get Severity & Status
    severity = "PENDING"
    vuln_status = cve.get('vulnStatus', 'Unknown')
    metrics = cve.get('metrics', {})

    if metrics.get('cvssMetricV31'):
        severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
    elif metrics.get('cvssMetricV30'):
        severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
    elif metrics.get('cvssMetricV2'):
        severity = metrics['cvssMetricV2'][0]['baseSeverity']

    safe_severity = html.escape(severity)
    safe_status = html.escape(vuln_status)

    icon = "⚠️"
    if severity in ['HIGH', 'CRITICAL']:
        icon = "🚨"
    elif severity == "LOW":
        icon = "ℹ️"
    elif severity == "PENDING":
        icon = "⏳"

    msg = (
        f"{icon} <b>New Tech Stack Alert</b>\n\n"
        f"🆔 <b>{safe_cve_id}</b>\n"
        f"📊 Status: <b>{safe_status}</b>\n"
        f"🔥 Severity: <b>{safe_severity}</b>\n\n"
        f"{safe_description}\n\n"
        f"<a href='https://nvd.nist.gov/vuln/detail/{cve_id}'>More Info</a>"
    )

    try:
        bot.send_message(CHAT_ID, msg, parse_mode='HTML')
        print(f"Sent alert for {cve_id}")
        save_seen_cve(cve_id)
    except Exception as e:
        print(f"Telegram Error: {e}")


def job():
    vuls = get_new_cves()
    if not vuls:
        print("No new vulnerabilities found.")

    for item in vuls:
        format_and_send(item)
        time.sleep(1)


if __name__ == "__main__":
    print(f"🛡️ Bot Running. Watching for: {', '.join(WATCHLIST)}")
    job()
    schedule.every(5).minute.do(job)
    while True:
        schedule.run_pending()
        time.sleep(1)