import time
import requests
from datetime import datetime, timedelta, timezone
from nvd_bot import config

_MAX_RETRIES = 3
_TIMEOUT = 60  # NVD API is slow; 20s was too short


def get_new_cves() -> list[dict]:
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    now = datetime.now(timezone.utc)
    lookback = config.get('cve_lookback_minutes', 6)
    start_window = now - timedelta(minutes=lookback)
    fmt = '%Y-%m-%dT%H:%M:%S.000'

    params = {
        'pubStartDate': start_window.strftime(fmt),
        'pubEndDate': now.strftime(fmt),
        'resultsPerPage': 100,
    }
    headers = {}
    if config.NVD_API_KEY:
        headers['apiKey'] = config.NVD_API_KEY

    print(f'[nvd] Checking {params["pubStartDate"]} → {params["pubEndDate"]}')

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=_TIMEOUT)
            if r.status_code == 200:
                return r.json().get('vulnerabilities', [])
            if r.status_code == 429:
                wait = 30 * attempt
                print(f'[nvd] Rate limited (429) — waiting {wait}s before retry {attempt}/{_MAX_RETRIES}')
                time.sleep(wait)
                continue
            print(f'[nvd] API error: {r.status_code}')
            return []
        except requests.exceptions.Timeout:
            wait = 10 * attempt
            print(f'[nvd] Timeout on attempt {attempt}/{_MAX_RETRIES} — NVD API is slow, retrying in {wait}s')
            if attempt < _MAX_RETRIES:
                time.sleep(wait)
        except Exception as e:
            print(f'[nvd] Connection error: {e}')
            return []

    print('[nvd] All retries exhausted — skipping this poll cycle')
    return []
