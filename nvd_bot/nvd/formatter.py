import html
import re
from datetime import datetime
from nvd_bot import config


def _severity_icon(severity: str) -> str:
    if severity in ('HIGH', 'CRITICAL'):
        return '🚨'
    if severity == 'MEDIUM':
        return '⚠️'
    if severity == 'LOW':
        return 'ℹ️'
    return '⏳'


def extract_meta(cve_item: dict) -> tuple[str, str, str, str]:
    """Returns (cve_id, description, severity, vuln_status)."""
    cve = cve_item.get('cve', {})
    cve_id = cve.get('id', '')
    vuln_status = cve.get('vulnStatus', 'Unknown')
    description = 'No description.'
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            description = d.get('value', 'No description.')
            break

    severity = 'PENDING'
    metrics = cve.get('metrics', {})
    if metrics.get('cvssMetricV31'):
        severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
    elif metrics.get('cvssMetricV30'):
        severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
    elif metrics.get('cvssMetricV2'):
        severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'PENDING')

    return cve_id, description, severity, vuln_status


def build_alert_message(cve_item: dict) -> str:
    cve_id, description, severity, vuln_status = extract_meta(cve_item)
    watchlist = config.get('watchlist', [])

    if len(description) > 400:
        description = description[:397] + '...'

    safe_desc = html.escape(description)
    sorted_kw = sorted(watchlist, key=len, reverse=True)
    for word in sorted_kw:
        pattern = r'(?i)\b(' + re.escape(word) + r')\b'
        safe_desc = re.sub(pattern, r'<b>\1</b>', safe_desc)

    icon = _severity_icon(severity)
    return (
        f'{icon} <b>New CVE Alert</b>\n\n'
        f'🆔 <b>{html.escape(cve_id)}</b>\n'
        f'📊 Status: <b>{html.escape(vuln_status)}</b>\n'
        f'🔥 Severity: <b>{html.escape(severity)}</b>\n\n'
        f'{safe_desc}\n\n'
        f"<a href='https://nvd.nist.gov/vuln/detail/{cve_id}'>More Info</a>"
    )


def build_daily_summary_message(daily_alerts: list[dict]) -> str:
    today = datetime.now().strftime('%Y-%m-%d')
    count = len(daily_alerts)

    all_keywords: set[str] = set()
    for alert in daily_alerts:
        all_keywords.update(alert.get('keywords', []))

    def to_tag(kw: str) -> str:
        return '#' + kw.replace(' ', '_').replace('.', '').replace('-', '')

    hashtags = ' '.join(to_tag(kw) for kw in sorted(all_keywords))

    lines = []
    for alert in daily_alerts:
        sev = alert['severity']
        icon = _severity_icon(sev)
        kw_tags = ' '.join(to_tag(kw) for kw in sorted(alert.get('keywords', [])))
        lines.append(f"{icon} <b>{html.escape(alert['cve_id'])}</b>  [{sev}]  {kw_tags}")

    return (
        f'📅 <b>Daily CVE Summary — {today}</b>\n\n'
        f'🔍 <b>{count}</b> alert(s) sent today:\n\n'
        + '\n'.join(lines)
        + f'\n\n{hashtags}'
    )
