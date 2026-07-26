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


def build_alert_message(cve_item: dict, signals: dict | None = None,
                        urgent: bool = False) -> str:
    cve_id, description, severity, vuln_status = extract_meta(cve_item)
    watchlist = config.get('watchlist', [])
    signals = signals or {}

    if len(description) > 400:
        description = description[:397] + '...'

    safe_desc = html.escape(description)
    sorted_kw = sorted(watchlist, key=len, reverse=True)
    for word in sorted_kw:
        pattern = r'(?i)\b(' + re.escape(word) + r')\b'
        safe_desc = re.sub(pattern, r'<b>\1</b>', safe_desc)

    icon = _severity_icon(severity)
    header = '⚡ <b>Exploited in the wild</b>' if signals.get('kev') else (
        '🔴 <b>Urgent CVE Alert</b>' if urgent else '<b>New CVE Alert</b>')

    exploit_line = ''
    if signals.get('kev'):
        exploit_line = '⚡ <b>In CISA KEV — confirmed exploited</b>\n'
    if signals.get('epss') is not None:
        exploit_line += f'📈 EPSS: <b>{signals["epss"]:.3f}</b>\n'

    return (
        f'{icon} {header}\n\n'
        f'🆔 <b>{html.escape(cve_id)}</b>\n'
        f'📊 Status: <b>{html.escape(vuln_status)}</b>\n'
        f'🔥 Severity: <b>{html.escape(severity)}</b>\n'
        f'{exploit_line}\n'
        f'{safe_desc}\n\n'
        f"<a href='https://nvd.nist.gov/vuln/detail/{cve_id}'>More Info</a>"
    )


def _source_link(cve_id: str, message_id: int | None) -> str:
    """Link to the original Telegram alert for this CVE, falling back to the
    NVD detail page if a message-level deep link can't be constructed
    (message_id missing, or CHAT_ID isn't a supergroup/channel)."""
    chat_id = str(config.CHAT_ID or '')
    if message_id and chat_id.startswith('-100'):
        internal_id = chat_id[4:]
        return f'https://t.me/c/{internal_id}/{message_id}'
    return f'https://nvd.nist.gov/vuln/detail/{cve_id}'


_SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
_TELEGRAM_LIMIT = 4096


def _to_tag(kw: str) -> str:
    return '#' + kw.replace(' ', '_').replace('.', '').replace('-', '')


def _sort_key(alert: dict) -> tuple:
    """Most urgent first: confirmed exploited, then severity, then EPSS."""
    return (
        0 if alert.get('kev') else 1,
        -_SEVERITY_ORDER.get((alert.get('severity') or '').upper(), 0),
        -(alert.get('epss') or 0.0),
        alert.get('cve_id', ''),
    )


def _short_desc(text: str, limit: int) -> str:
    """Collapse whitespace and truncate on a word boundary."""
    if not text:
        return ''
    collapsed = ' '.join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rsplit(' ', 1)[0] + '…'


def _alert_block(alert: dict, repo: str | None = None, indent: str = '') -> list[str]:
    """One CVE rendered as a small block: the identifier line, what is
    actually affected, and what the problem is.

    The identifier alone is useless in a digest — you cannot tell a critical
    RCE in a dependency you ship from an IDE bug that merely mentions your
    stack in passing.
    """
    sev = alert.get('severity', 'PENDING')
    icon = _severity_icon(sev)
    cve_id = alert.get('cve_id', '')
    link = _source_link(cve_id, alert.get('message_id'))
    cve_link = f'<a href="{html.escape(link)}">{html.escape(cve_id)}</a>'

    extras = []
    if alert.get('kev'):
        extras.append('⚡KEV')
    if alert.get('epss') is not None:
        extras.append(f'EPSS {alert["epss"]:.2f}')
    extra_str = ('  ' + '  '.join(extras)) if extras else ''

    kw_tags = ' '.join(_to_tag(kw) for kw in sorted(alert.get('keywords', [])))
    kw_str = f'  {kw_tags}' if kw_tags else ''

    lines = [f'{indent}{icon} <b>{cve_link}</b>  [{sev}]{extra_str}{kw_str}']

    # What's affected. Inside a repo group, prefer the package as it appears
    # in that repo — the installed version is the part you act on.
    detail = (alert.get('repo_packages') or {}).get(repo or '', [])
    if detail:
        for entry in detail:
            lines.append(f'{indent}    📦 <code>{html.escape(entry)}</code>')
    elif alert.get('packages'):
        pkgs = ', '.join(alert['packages'])
        lines.append(f'{indent}    📦 <code>{html.escape(pkgs)}</code>')

    limit = config.get('summary_description_chars', 170)
    desc = _short_desc(alert.get('title', ''), limit)
    if desc:
        lines.append(f'{indent}    <i>{html.escape(desc)}</i>')

    return lines


def _chunk(header: str, blocks: list[list[str]], footer: str) -> list[str]:
    """Pack blocks into messages under Telegram's 4096-char limit, splitting
    only on whole lines so HTML tags stay balanced. A digest that grew past
    the limit would otherwise fail to send entirely — and with per-CVE alerts
    off, that is the whole day's notification gone."""
    messages: list[str] = []
    current = header

    for block in blocks:
        for line in block:
            candidate = current + '\n' + line
            if len(candidate) + len(footer) > _TELEGRAM_LIMIT:
                messages.append(current)
                current = line
            else:
                current = candidate

    if footer and len(current) + len(footer) + 2 <= _TELEGRAM_LIMIT:
        current += '\n\n' + footer
    elif footer:
        messages.append(current)
        current = footer

    messages.append(current)
    return [m for m in messages if m.strip()]


def build_daily_summary_message(daily_alerts: list[dict]) -> list[str]:
    """Render the digest as one or more Telegram-sized messages."""
    today = datetime.now().strftime('%Y-%m-%d')
    total = len(daily_alerts)

    affecting = [a for a in daily_alerts if a.get('repos')]
    watch_only = [a for a in daily_alerts if not a.get('repos')]
    kev_count = sum(1 for a in daily_alerts if a.get('kev'))

    header = f'📅 <b>Daily CVE Summary — {today}</b>\n\n🔍 <b>{total}</b> alert(s)'
    if affecting:
        header += f' · <b>{len(affecting)}</b> affecting your repos'
    if kev_count:
        header += f' · ⚡ <b>{kev_count}</b> exploited'

    blocks: list[list[str]] = []

    if affecting:
        by_repo: dict[str, list[dict]] = {}
        for alert in affecting:
            for repo in alert.get('repos', []):
                by_repo.setdefault(repo, []).append(alert)

        block = ['', '🔴 <b>Affects your repos</b>']
        for repo in sorted(by_repo):
            block.append(f'\n<b>{html.escape(repo)}</b>')
            for alert in sorted(by_repo[repo], key=_sort_key):
                block.extend(_alert_block(alert, repo=repo, indent='  '))
        blocks.append(block)

    if watch_only:
        block = ['', '📋 <b>Watchlist only</b>']
        for alert in sorted(watch_only, key=_sort_key):
            block.extend(_alert_block(alert))
        blocks.append(block)

    all_keywords: set[str] = set()
    for alert in daily_alerts:
        all_keywords.update(alert.get('keywords', []))
    footer = ' '.join(_to_tag(kw) for kw in sorted(all_keywords))

    return _chunk(header, blocks, footer)
