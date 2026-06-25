import requests
from datetime import datetime, timedelta, timezone
from nvd_bot import config


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

    try:
        print(f'[nvd] Checking {params["pubStartDate"]} → {params["pubEndDate"]}')
        r = requests.get(url, params=params, headers=headers, timeout=20)
        if r.status_code == 200:
            return r.json().get('vulnerabilities', [])
        print(f'[nvd] API error: {r.status_code}')
        return []
    except Exception as e:
        print(f'[nvd] Connection error: {e}')
        return []
