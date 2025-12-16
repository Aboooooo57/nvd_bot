import requests
import telebot
import schedule
import time
import csv  # <--- CHANGED: Using CSV now
import os
import html
import re
from datetime import datetime, timedelta, timezone

# ================= CONFIGURATION =================
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')
NVD_API_KEY = os.getenv('NVD_API_KEY')

# CHANGED: File extension is now .csv
DATA_FILE = 'data/seen_cves.csv'

# WATCHLIST (Your Keywords)
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
    """
    Reads the CSV and returns a list of just the CVE IDs.
    """
    if not os.path.exists(DATA_FILE):
        return []

    seen_ids = []
    try:
        with open(DATA_FILE, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Skip header if it exists
            next(reader, None)
            for row in reader:
                if row:  # Avoid empty lines
                    seen_ids.append(row[0])  # Column 0 is the ID
        return seen_ids
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []


def save_seen_cve(cve_id):
    """
    Appends the new CVE to the CSV.
    Enforces a Limit (FILO/Rolling Buffer): Keeps only the last 1000 entries.
    """
    # 1. Read all existing rows
    rows = []
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)

    # 2. If file is empty, add Header
    if not rows:
        rows.append(["CVE_ID", "TIMESTAMP"])

    # 3. Add the new entry (ID + Current Time)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    rows.append([cve_id, timestamp])

    # 4. Enforce Limit (Keep Header + Last 1000)
    # rows[0] is header. rows[1:] is data.
    header = rows[0]
    data = rows[1:]

    if len(data) > 1000:
        # Slice to keep only the last 1000 items
        data = data[-1000:]

    # 5. Write everything back to file
    with open(DATA_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(data)


def get_new_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Time window calculation (UTC)
    now = datetime.now(timezone.utc)

    # Check last 6 minutes (to cover the 5 min schedule safely)
    start_window = now - timedelta(minutes=6)

    fmt = '%Y-%m-%dT%H:%M:%S.000'
    pub_end_date = now.strftime(fmt)
    pub_start_date = start_window.strftime(fmt)

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
    if not description: return False
    desc_lower = description.lower()
    for keyword in WATCHLIST:
        # Use Regex for exact word matching (prevents "react" matching "reaction")
        pattern = r'(?i)\b' + re.escape(keyword) + r'\b'
        if re.search(pattern, desc_lower):
            return True
    return False


def format_and_send(cve_item):
    cve = cve_item.get('cve', {})
    cve_id = cve.get('id')

    if not cve_id: return

    # Check Duplicates (Reads from CSV)
    seen_ids = load_seen_cves()
    if cve_id in seen_ids:
        print(f"Skipping duplicate: {cve_id}")
        return

    # Extract Description
    raw_description = "No description."
    for desc in cve.get('descriptions', []):
        if desc.get('lang') == 'en':
            raw_description = desc.get('value')
            break

    # Filter Logic
    if not is_relevant(raw_description):
        print(f"Skipping {cve_id} (Not in stack)")
        save_seen_cve(cve_id)  # Save to CSV so we don't check again
        return

    # Format Message
    if len(raw_description) > 400:
        raw_description = raw_description[:397] + "..."

    safe_description = html.escape(raw_description)

    # Bold Keywords
    sorted_keywords = sorted(WATCHLIST, key=len, reverse=True)
    for word in sorted_keywords:
        pattern = r'(?i)\b(' + re.escape(word) + r')\b'
        safe_description = re.sub(pattern, r'<b>\1</b>', safe_description)

    safe_cve_id = html.escape(cve_id)

    # Severity & Status
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
        save_seen_cve(cve_id)  # Save to CSV
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
    print(f"🛡️ Bot Running (CSV Mode). Watching: {', '.join(WATCHLIST)}")

    job()
    schedule.every(5).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)