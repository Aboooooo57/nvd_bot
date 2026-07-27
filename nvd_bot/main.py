from __future__ import annotations
import csv
import html
import json
import os
import re
import schedule
import threading
import time
from datetime import datetime, timezone

from nvd_bot import config
from nvd_bot.nvd.client import get_new_cves, get_cve_by_id
from nvd_bot.nvd import poll_state
from nvd_bot.nvd.filter import is_relevant_to_watchlist, extract_affected_packages
from nvd_bot.nvd.formatter import build_alert_message, build_daily_summary_message, extract_meta
from nvd_bot.nvd import enrichment, mutes
from nvd_bot.repos.registry import RepoRegistry
from nvd_bot.repos.github_client import GithubClient
from nvd_bot.repos.issue_ledger import IssueLedger
from nvd_bot.fixes.llm_client import LLMClient
from nvd_bot.matching.matcher import match_cve_to_repos
from nvd_bot import bot as tgbot
from nvd_bot.scheduler import poll_commits
from nvd_bot.repos.git_account_store import GitAccountStore

# Alerts accumulated since the last daily summary. Mirrored to disk on every
# append: the summary is now the primary notification channel, so a restart
# part-way through the day must not silently swallow it.
_daily_alerts: list[dict] = []
_daily_lock = threading.Lock()

_SEVERITY_RANK = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

# Which (repo, CVE) pairs already have an issue — keeps re-detections from
# opening duplicates.
_ledger = IssueLedger()


# ── CSV deduplication ─────────────────────────────────────────────────────────

def _load_seen() -> set[str]:
    if not os.path.exists(config.SEEN_CVES_FILE):
        return set()
    seen = set()
    try:
        with open(config.SEEN_CVES_FILE, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if row:
                    seen.add(row[0])
    except Exception as e:
        print(f'[main] CSV read error: {e}')
    return seen


def _save_seen(cve_id: str):
    rows = []
    if os.path.exists(config.SEEN_CVES_FILE):
        with open(config.SEEN_CVES_FILE, 'r', newline='', encoding='utf-8') as f:
            rows = list(csv.reader(f))
    if not rows:
        rows.append(['CVE_ID', 'TIMESTAMP'])
    rows.append([cve_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    header, data = rows[0], rows[1:]
    limit = config.get('seen_cve_limit', 1000)
    if len(data) > limit:
        data = data[-limit:]
    os.makedirs(os.path.dirname(config.SEEN_CVES_FILE), exist_ok=True)
    with open(config.SEEN_CVES_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(data)


# ── Daily alert accumulation (survives restarts) ──────────────────────────────

def _load_daily_alerts() -> list[dict]:
    if not os.path.exists(config.DAILY_ALERTS_FILE):
        return []
    try:
        with open(config.DAILY_ALERTS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f'[main] daily alerts read error: {e}')
        return []


def _write_daily_alerts_unlocked(alerts: list[dict]):
    """Atomic write — a crash mid-write must not leave a truncated file that
    costs us the whole day's summary."""
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = config.DAILY_ALERTS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(alerts, f)
        os.replace(tmp, config.DAILY_ALERTS_FILE)
    except Exception as e:
        print(f'[main] daily alerts write error: {e}')


def _record_daily_alert(alert: dict):
    """Upsert by CVE id — a re-checked CVE replaces its earlier PENDING entry
    rather than appearing in the summary twice."""
    with _daily_lock:
        for i, existing in enumerate(_daily_alerts):
            if existing.get('cve_id') == alert.get('cve_id'):
                _daily_alerts[i] = alert
                break
        else:
            _daily_alerts.append(alert)
        _write_daily_alerts_unlocked(_daily_alerts)


def remove_daily_alert(cve_id: str) -> dict | None:
    """Take a CVE out of the pending digest and return its entry, so a
    dismissal can store it and put it back later."""
    global _daily_alerts
    with _daily_lock:
        removed = next((a for a in _daily_alerts if a.get('cve_id') == cve_id), None)
        if removed is None:
            return None
        _daily_alerts = [a for a in _daily_alerts if a.get('cve_id') != cve_id]
        _write_daily_alerts_unlocked(_daily_alerts)
        return removed


def restore_daily_alert(alert: dict):
    """Put a previously dismissed entry back into the pending digest."""
    if alert and alert.get('cve_id'):
        _record_daily_alert(alert)


def _drain_daily_alerts() -> list[dict]:
    global _daily_alerts
    with _daily_lock:
        alerts = list(_daily_alerts)
        _daily_alerts = []
        _write_daily_alerts_unlocked([])
    return alerts


def _meets_threshold(severity: str) -> bool:
    thr = config.get('severity_threshold', 'MEDIUM')
    return _SEVERITY_RANK.get((severity or '').upper(), 0) >= _SEVERITY_RANK.get(thr.upper(), 2)


def _is_immediate(severity: str, enrichment: dict) -> bool:
    """Should this bypass the digest and go out now?"""
    if config.get('immediate_on_kev', True) and enrichment.get('kev'):
        return True
    bar = config.get('immediate_severity', 'CRITICAL')
    if not bar:
        return False
    return (_SEVERITY_RANK.get((severity or '').upper(), 0)
            >= _SEVERITY_RANK.get(str(bar).upper(), 99))


def _is_unscored(severity: str) -> bool:
    """True when NVD hasn't assigned a CVSS severity yet — common for the
    first few days after publication."""
    return (severity or '').upper() not in _SEVERITY_RANK


# ── Core CVE processing pipeline ──────────────────────────────────────────────

def process_cve(cve_item: dict, registry: RepoRegistry, gh: GithubClient, llm: LLMClient):
    """Handle a freshly-published CVE, skipping any we've already recorded."""
    cve_id, _, _, _ = extract_meta(cve_item)
    if not cve_id:
        return
    if cve_id in _load_seen():
        return
    _evaluate_cve(cve_item, registry, gh, llm)


def _evaluate_cve(cve_item: dict, registry: RepoRegistry, gh: GithubClient,
                  llm: LLMClient, force: bool = False):
    """Match a CVE against repos and the watchlist, then notify/act.

    force=True re-runs a CVE already present in seen_cves.csv — used by the
    pending re-check, where the whole point is to reconsider a CVE now that
    NVD has finally scored it.
    """
    from concurrent.futures import ThreadPoolExecutor
    cve_id, description, severity, _ = extract_meta(cve_item)
    if not cve_id:
        return

    affected = extract_affected_packages(cve_item)
    repos = registry.list_repos()
    matches = match_cve_to_repos(cve_item, repos, affected) if affected else []
    watchlist_hit = is_relevant_to_watchlist(description)

    if not matches and not watchlist_hit:
        if not force:
            _save_seen(cve_id)
        poll_state.drop_pending(cve_id)
        return

    # Reader-driven suppression. Both only ever apply to watchlist noise —
    # once a CVE matches a tracked repo's dependencies it is reported
    # regardless, since that is the signal this bot exists to deliver.
    if not matches:
        if mutes.is_dismissed(cve_id):
            print(f'[main] {cve_id}: dismissed by user — skipping')
            if not force:
                _save_seen(cve_id)
            poll_state.drop_pending(cve_id)
            return
        muted = mutes.matched_ignored(list(affected or []))
        if muted:
            print(f'[main] {cve_id}: product "{muted}" is muted — skipping')
            if not force:
                _save_seen(cve_id)
            poll_state.drop_pending(cve_id)
            return

    signals = enrichment.enrich(cve_id)

    # Per-CVE alerts are opt-in, but confirmed-exploited or top-severity CVEs
    # still break through immediately — waiting until 23:55 to mention one of
    # those would defeat the point of watching at all.
    urgent = _is_immediate(severity, signals)
    message_id = None
    if config.get('per_cve_alerts', False) or urgent:
        # Only offer mute/dismiss on watchlist noise — a repo match shouldn't
        # be silenceable with one tap.
        keyboard = None
        if not matches:
            from nvd_bot.bot.callbacks.cve import build_keyboard
            keyboard = build_keyboard(cve_id, sorted(affected or []))
        sent = tgbot.send(build_alert_message(cve_item, signals, urgent=urgent),
                          reply_markup=keyboard)
        message_id = sent.message_id if sent else None
    if not force:
        _save_seen(cve_id)

    # No CVSS score yet — keep it on the re-check list so a score assigned
    # days from now still reaches the severity gate below.
    if _is_unscored(severity):
        poll_state.add_pending(cve_id)
    else:
        poll_state.drop_pending(cve_id)

    watchlist = config.get('watchlist', [])
    matched_kw = [kw for kw in watchlist
                  if re.search(r'(?i)\b' + re.escape(kw) + r'\b', description)]
    # Everything the digest needs to be readable on its own. Without the
    # affected product and a description, a summary line is just an opaque
    # identifier — you can't tell an RCE in something you ship from an IDE
    # bug that merely name-drops your stack.
    repo_packages: dict[str, list[str]] = {}
    for m in matches:
        entries = []
        for pkg in m.matched_packages:
            ver = m.current_versions.get(pkg, 'unknown')
            specs = ', '.join(m.affected_specs.get(pkg, [])) or 'unknown range'
            entries.append(f'{pkg} {ver} — vulnerable: {specs}')
        if entries:
            repo_packages[m.repo.name] = entries

    _record_daily_alert({
        'cve_id': cve_id,
        'severity': severity,
        'keywords': matched_kw,
        'message_id': message_id,
        'kev': signals.get('kev'),
        'epss': signals.get('epss'),
        'repos': [m.repo.name for m in matches],
        'packages': sorted(affected)[:4] if affected else [],
        'repo_packages': repo_packages,
        'title': ' '.join((description or '').split())[:400],
    })

    print(f'[main] {cve_id} ({severity}){" [KEV]" if signals.get("kev") else ""}: '
          f'{len(matches)} repo match(es)')

    if not matches:
        return

    min_epss = config.get('min_epss_for_issue', 0.0) or 0.0
    epss = signals.get('epss')
    if not _meets_threshold(severity):
        print(f'[main] {cve_id}: below severity threshold '
              f'({config.get("severity_threshold", "MEDIUM")}) — no issue created')
    elif min_epss > 0 and epss is not None and epss < min_epss and not signals.get('kev'):
        # Only reachable if the operator opted in by raising min_epss_for_issue.
        print(f'[main] {cve_id}: EPSS {epss:.3f} below min_epss_for_issue '
              f'({min_epss}) — no issue created')
    else:
        executor = ThreadPoolExecutor(max_workers=2)
        for match in matches:
            executor.submit(_handle_match, match, cve_item, gh, signals)


def _handle_match(match, cve_item: dict, gh: GithubClient, signals: dict | None = None):
    from nvd_bot.repos.scanner import _split_name
    cve_id, description, severity, _ = extract_meta(cve_item)
    owner, repo_name = _split_name(match.repo.name)
    if not owner:
        return

    # Already reported on this repo? Don't open a second issue for the same
    # vulnerability — but if the severity has since been revised upward, say
    # so on the existing issue.
    existing = _ledger.get(match.repo.id, cve_id)
    if existing:
        old_sev = existing.get('severity', '')
        if _SEVERITY_RANK.get(severity.upper(), 0) > _SEVERITY_RANK.get(old_sev.upper(), 0):
            print(f'[main] {cve_id} in {match.repo.name}: {old_sev} → {severity}, commenting')
            gh.comment_on_issue(
                owner, repo_name, existing['issue_url'],
                f'**Severity updated: {old_sev} → {severity}**\n\n'
                f'NVD has revised the score for {cve_id}.\n\n'
                f'*Updated automatically by NVD Bot*',
                token=match.repo.github_token,
            )
            _ledger.update_severity(match.repo.id, cve_id, severity)
            tgbot.send(
                f'🔺 <b>Severity raised</b> for <code>{html.escape(cve_id)}</code> '
                f'in <b>{html.escape(match.repo.name)}</b>: '
                f'{html.escape(old_sev)} → {html.escape(severity)}\n'
                f'<a href="{html.escape(existing["issue_url"])}">View Issue →</a>'
            )
        else:
            print(f'[main] {cve_id} already reported in {match.repo.name} — skipping')
        return

    pkg_lines = []
    for pkg in match.matched_packages:
        ver = match.current_versions.get(pkg, 'unknown')
        specs = match.affected_specs.get(pkg, [])
        spec_str = ', '.join(specs) if specs else 'unknown range'
        pkg_lines.append(f'- **{pkg}** (installed: `{ver}`, vulnerable: `{spec_str}`)')

    source_files = sorted(set(match.source_files.values()))

    signals = signals or {}
    exploit_lines = []
    if signals.get('kev'):
        exploit_lines.append(
            '> ⚡ **Listed in the CISA Known Exploited Vulnerabilities '
            'catalogue — confirmed exploited in the wild.**')
    if signals.get('epss') is not None:
        pct = signals.get('epss_percentile')
        pct_str = f' (higher than {pct:.1%} of all CVEs)' if pct is not None else ''
        exploit_lines.append(
            f'EPSS: **{signals["epss"]:.3f}** probability of exploitation '
            f'in the next 30 days{pct_str}.')
    exploit_block = ('\n\n'.join(exploit_lines) + '\n\n') if exploit_lines else ''

    kev_tag = ' [KEV]' if signals.get('kev') else ''
    title = f'Security{kev_tag}: {cve_id} affects {", ".join(match.matched_packages[:3])}'
    body = (
        f'## {cve_id} — {severity}\n\n'
        + exploit_block
        + f'{description}\n\n'
        f'### Affected packages\n\n'
        + '\n'.join(pkg_lines) + '\n\n'
        + f'### Source files\n\n'
        + '\n'.join(f'- `{f}`' for f in source_files) + '\n\n'
        + f'🔗 https://nvd.nist.gov/vuln/detail/{cve_id}\n\n'
        + '*Detected automatically by NVD Bot*'
    )

    token = match.repo.github_token
    print(f'[main] Creating issue for {cve_id} in {match.repo.name}')
    issue_url = gh.create_issue(owner, repo_name, title, body,
                                labels=['security'], token=token)
    if issue_url:
        _ledger.record(match.repo.id, cve_id, issue_url, severity)
        tgbot.send(
            f'🔒 <b>Security issue created</b> in <b>{html.escape(match.repo.name)}</b>\n'
            f'CVE: <code>{html.escape(cve_id)}</code> | Severity: {html.escape(severity)}\n'
            f'Packages: <code>{html.escape(", ".join(match.matched_packages))}</code>\n'
            f'<a href="{html.escape(issue_url)}">View Issue →</a>'
        )
        print(f'[main] Issue created: {issue_url}')
    else:
        tgbot.send(
            f'⚠️ Could not create issue for <b>{html.escape(match.repo.name)}</b> '
            f'/ {html.escape(cve_id)}'
        )


# ── Scheduled jobs ────────────────────────────────────────────────────────────

def _cve_job(registry, gh, llm):
    items = get_new_cves()
    if not items:
        print('[main] No new CVEs.')
        return
    for item in items:
        process_cve(item, registry, gh, llm)
        time.sleep(1)


def _recheck_pending_job(registry, gh, llm):
    """Re-fetch CVEs that were published without a CVSS score and re-evaluate
    any that have since been scored."""
    retention = config.get('pending_retention_days', 14)
    aged_out = poll_state.prune_pending(retention)
    if aged_out:
        print(f'[main] Pending re-check: dropped {len(aged_out)} CVE(s) '
              f'still unscored after {retention}d: {", ".join(aged_out[:5])}')

    pending = poll_state.list_pending()
    if not pending:
        print('[main] Pending re-check: nothing to do.')
        return

    print(f'[main] Pending re-check: {len(pending)} CVE(s)')
    scored = 0
    for cve_id in pending:
        item = get_cve_by_id(cve_id)
        if item is None:
            continue  # transient failure — stays pending, retried tomorrow
        _, _, severity, _ = extract_meta(item)
        if _is_unscored(severity):
            continue
        print(f'[main] {cve_id} now scored {severity} — re-evaluating')
        _evaluate_cve(item, registry, gh, llm, force=True)
        scored += 1
        time.sleep(1)  # stay well inside NVD rate limits

    if scored:
        print(f'[main] Pending re-check: {scored} CVE(s) newly scored')


def send_summary(drain: bool = True) -> bool:
    """Render and send the digest. Returns False if there was nothing to send.

    drain=False previews without clearing, so a mid-day /summary peek can't
    cost you the scheduled message.
    """
    if drain:
        alerts = _drain_daily_alerts()
    else:
        with _daily_lock:
            alerts = list(_daily_alerts)

    if not alerts:
        return False

    for chunk in build_daily_summary_message(alerts):
        tgbot.send(chunk, disable_web_page_preview=True)
    return True


def _daily_summary_job():
    if not send_summary(drain=True):
        print('[main] No alerts today, skipping summary.')


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    from nvd_bot.version import version_string
    print(f'[main] NVD Bot {version_string()} starting.')

    config.load()
    print('[main] Config loaded.')

    restored = _load_daily_alerts()
    if restored:
        _daily_alerts.extend(restored)
        print(f'[main] Restored {len(restored)} pending alert(s) for today\'s summary.')

    registry = RepoRegistry()
    gh = GithubClient()
    llm = LLMClient()
    git_store = GitAccountStore()

    bot = tgbot.init(registry, gh, llm, git_store)
    from nvd_bot.bot import state as bot_state
    bot_state._summary_job = send_summary
    threading.Thread(
        target=lambda: bot.infinity_polling(none_stop=True, timeout=60),
        daemon=True,
        name='telegram-polling',
    ).start()
    print('[main] Telegram bot polling started.')

    _cve_job(registry, gh, llm)

    poll_interval = config.get('nvd_poll_interval_minutes', 5)
    commit_interval = config.get('commit_poll_interval_minutes', 15)
    summary_time = config.get('daily_summary_time', '23:55')

    recheck_time = config.get('pending_recheck_time', '04:00')

    schedule.every(poll_interval).minutes.do(_cve_job, registry, gh, llm)
    schedule.every(commit_interval).minutes.do(poll_commits, registry, gh)
    schedule.every().day.at(summary_time).do(_daily_summary_job)
    schedule.every().day.at(recheck_time).do(_recheck_pending_job, registry, gh, llm)

    print(f'[main] Scheduled: CVE every {poll_interval}m, '
          f'commit poll every {commit_interval}m, summary at {summary_time}, '
          f'pending re-check at {recheck_time}')

    while True:
        schedule.run_pending()
        time.sleep(1)
