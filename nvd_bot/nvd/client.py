import time
import requests
from datetime import datetime, timedelta, timezone
from nvd_bot import config
from nvd_bot.nvd import poll_state

_MAX_RETRIES = 3
_TIMEOUT = 60  # NVD API is slow; 20s was too short
_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_FMT = '%Y-%m-%dT%H:%M:%S.000'


def _request(params: dict) -> list[dict] | None:
    """Returns the vulnerability list, or None if the request failed.

    The None/[] distinction matters: [] means "nothing published in that
    window", None means "we never found out". Only the former may advance the
    poll watermark.
    """
    headers = {}
    if config.NVD_API_KEY:
        headers['apiKey'] = config.NVD_API_KEY

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            r = requests.get(_API, params=params, headers=headers, timeout=_TIMEOUT)
            if r.status_code == 200:
                return r.json().get('vulnerabilities', [])
            if r.status_code == 429:
                wait = 30 * attempt
                print(f'[nvd] Rate limited (429) — waiting {wait}s before retry {attempt}/{_MAX_RETRIES}')
                time.sleep(wait)
                continue
            print(f'[nvd] API error: {r.status_code}')
            return None
        except requests.exceptions.Timeout:
            wait = 10 * attempt
            print(f'[nvd] Timeout on attempt {attempt}/{_MAX_RETRIES} — NVD API is slow, retrying in {wait}s')
            if attempt < _MAX_RETRIES:
                time.sleep(wait)
        except Exception as e:
            print(f'[nvd] Connection error: {e}')
            return None

    print('[nvd] All retries exhausted — skipping this poll cycle')
    return None


def _report_gap(skipped_from: datetime, skipped_until: datetime):
    """Downtime longer than max_catchup_hours leaves CVEs permanently
    unexamined. Say so out loud rather than sliding the window in silence."""
    msg = (
        f'⚠️ <b>CVE feed gap</b>\n\n'
        f'The bot was not polling from <code>{skipped_from.strftime(_FMT)}</code> '
        f'to <code>{skipped_until.strftime(_FMT)}</code> UTC, which exceeds '
        f'<code>max_catchup_hours</code>. CVEs published in that window were '
        f'not checked.'
    )
    print(f'[nvd] GAP: {skipped_from} → {skipped_until} not covered')
    try:
        from nvd_bot import bot as tgbot
        tgbot.send(msg)
    except Exception as e:
        print(f'[nvd] could not report gap: {e}')


def get_new_cves() -> list[dict]:
    now = datetime.now(timezone.utc)
    start, skipped_until = poll_state.compute_window(now)
    if skipped_until is not None:
        last = poll_state.get_last_poll()
        if last:
            _report_gap(last, skipped_until)

    params = {
        'pubStartDate': start.strftime(_FMT),
        'pubEndDate': now.strftime(_FMT),
        'resultsPerPage': 2000,
    }
    print(f'[nvd] Checking {params["pubStartDate"]} → {params["pubEndDate"]}')

    items = _request(params)
    if items is None:
        # Watermark deliberately left where it is — this window gets retried.
        return []

    poll_state.set_last_poll(now)
    return items


def get_cve_by_id(cve_id: str) -> dict | None:
    """Fetch a single CVE, used to re-check ones published without a score."""
    items = _request({'cveId': cve_id})
    if not items:
        return None
    return items[0]
