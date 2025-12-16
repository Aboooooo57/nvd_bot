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
    "fastapi",
    "next.js", "nextjs",
    "react", "reactjs",
    "python",
    "typescript",
    "node.js", "nodejs",  # Added common related tech
    "django", "flask"  # Added common Python frameworks
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
    Checks if the description contains any keyword from the WATCHLIST.
    """
    if not description:
        return False

    desc_lower = description.lower()

    for keyword in WATCHLIST:
        # We add spaces to avoid partial matches (e.g., matching "react" in "reaction")
        # But for simple tech names, direct containment is usually fine.
        if keyword in desc_lower:
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

    # 3. --- FILTER LOGIC ---
    # If the description does NOT contain our keywords, skip it.
    if not is_relevant(raw_description):
        print(f"Skipping {cve_id} (Not in stack)")
        # We mark it as seen so we don't process it again
        save_seen_cve(cve_id)
        return
    # -----------------------

    # Format Data
    if len(raw_description) > 400:
        raw_description = raw_description[:397] + "..."

    safe_description = html.escape(raw_description)
    safe_cve_id = html.escape(cve_id)

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