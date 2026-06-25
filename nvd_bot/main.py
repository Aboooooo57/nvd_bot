from __future__ import annotations
import csv
import html
import os
import re
import schedule
import threading
import time
from datetime import datetime, timezone

from nvd_bot import config
from nvd_bot.nvd.client import get_new_cves
from nvd_bot.nvd.filter import is_relevant_to_watchlist, extract_affected_packages
from nvd_bot.nvd.formatter import build_alert_message, build_daily_summary_message, extract_meta
from nvd_bot.repos.registry import RepoRegistry
from nvd_bot.repos.github_client import GithubClient
from nvd_bot.fixes.pending import PendingFixStore
from nvd_bot.fixes.llm_client import LLMClient
from nvd_bot.matching.matcher import match_cve_to_repos
from nvd_bot import telegram_bot as tgbot
from nvd_bot.scheduler import poll_commits

# In-memory daily alert list
_daily_alerts: list[dict] = []
_daily_lock = threading.Lock()


# ── CSV deduplication (unchanged format from original) ────────────────────────

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


# ── Core CVE processing pipeline ──────────────────────────────────────────────

def process_cve(cve_item: dict, registry: RepoRegistry,
                pending: PendingFixStore, gh: GithubClient, llm: LLMClient):
    from concurrent.futures import ThreadPoolExecutor
    cve_id, description, severity, _ = extract_meta(cve_item)
    if not cve_id:
        return

    seen = _load_seen()
    if cve_id in seen:
        return

    # Filter: relevant to any tracked repo OR watchlist keyword
    affected = extract_affected_packages(cve_item)
    repos = registry.list_repos()
    matches = match_cve_to_repos(cve_item, repos, affected) if affected else []
    watchlist_hit = is_relevant_to_watchlist(description)

    if not matches and not watchlist_hit:
        _save_seen(cve_id)
        return

    # Send standard CVE alert
    msg = build_alert_message(cve_item)
    tgbot.send(msg)
    _save_seen(cve_id)

    watchlist = config.get('watchlist', [])
    matched_kw = [kw for kw in watchlist
                  if re.search(r'(?i)\b' + re.escape(kw) + r'\b', description)]
    with _daily_lock:
        _daily_alerts.append({
            'cve_id': cve_id,
            'severity': severity,
            'keywords': matched_kw,
        })

    print(f'[main] {cve_id} ({severity}): {len(matches)} repo match(es)')

    # Submit fix generation for each matching repo (non-blocking)
    if matches and llm and config.OPENROUTER_API_KEY or config.LITELLM_API_KEY:
        executor = ThreadPoolExecutor(max_workers=2)
        for match in matches:
            executor.submit(_handle_match, match, cve_item, pending, gh, llm)


def _handle_match(match, cve_item: dict, pending: PendingFixStore,
                   gh: GithubClient, llm: LLMClient):
    from nvd_bot.fixes.proposer import generate_fix
    print(f'[main] Generating fix for {match.cve_id} in {match.repo.name}')
    try:
        fix = generate_fix(match, cve_item, gh, llm)
    except Exception as e:
        print(f'[main] Fix generation error: {e}')
        tgbot.send(f'⚠️ Could not generate fix for <b>{html.escape(match.repo.name)}</b> '
                   f'/ {html.escape(match.cve_id)}: {html.escape(str(e))}')
        return

    if not fix:
        return

    pending.add(fix)

    auto_pr = match.repo.get_config('auto_pr', config.get('auto_pr', False))
    if auto_pr:
        _auto_apply(fix, match.repo, gh, pending)
    else:
        tgbot.send_fix_proposal(fix)


def _auto_apply(fix, repo, gh: GithubClient, pending: PendingFixStore):
    from nvd_bot.repos.scanner import _split_name
    owner, repo_name = _split_name(repo.name)
    token = repo.github_token
    base_branch = repo.get_config('pr_base_branch', config.get('pr_base_branch', 'main'))
    prefix = repo.get_config('pr_branch_prefix', config.get('pr_branch_prefix', 'security/fix'))
    branch = f'{prefix}-{fix.cve_id.lower()}-{fix.fix_id}'

    sha = gh.get_latest_commit_sha(owner, repo_name, token=token, branch=base_branch)
    if not sha:
        pending.update_status(fix.fix_id, 'failed')
        return

    gh.create_branch(owner, repo_name, branch, sha, token=token)
    ok = gh.commit_file(owner, repo_name, fix.file_path, fix.fixed_content,
                         f'fix: patch {fix.cve_id}', branch, token=token)
    if not ok:
        pending.update_status(fix.fix_id, 'failed')
        return

    pr_url = gh.create_pull_request(
        owner, repo_name,
        title=f'Security: fix {fix.cve_id} in {fix.file_path}',
        body=f'## Auto-fix\n\n**CVE:** {fix.cve_id}\n\n{fix.explanation}\n\n*Auto-applied by NVD Bot*',
        head=branch, base=base_branch, token=token,
    )
    if pr_url:
        pending.update_status(fix.fix_id, 'applied', pr_url=pr_url)
        tgbot.send(f'⚡ Auto-PR created for <b>{html.escape(repo.name)}</b>\n'
                   f'{html.escape(fix.cve_id)}: <a href="{html.escape(pr_url)}">View PR</a>')
    else:
        pending.update_status(fix.fix_id, 'failed')


# ── Scheduled jobs ────────────────────────────────────────────────────────────

def _cve_job(registry, pending, gh, llm):
    items = get_new_cves()
    if not items:
        print('[main] No new CVEs.')
        return
    for item in items:
        process_cve(item, registry, pending, gh, llm)
        time.sleep(1)


def _daily_summary_job():
    global _daily_alerts
    with _daily_lock:
        alerts = list(_daily_alerts)
        _daily_alerts = []
    if not alerts:
        print('[main] No alerts today, skipping summary.')
        return
    msg = build_daily_summary_message(alerts)
    tgbot.send(msg)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    config.load()
    print('[main] Config loaded.')

    registry = RepoRegistry()
    pending = PendingFixStore()
    gh = GithubClient()
    llm = LLMClient()

    # Init and start Telegram bot polling in background thread
    bot = tgbot.init(registry, pending, gh, llm)
    threading.Thread(
        target=lambda: bot.infinity_polling(none_stop=True, timeout=60),
        daemon=True,
        name='telegram-polling',
    ).start()
    print('[main] Telegram bot polling started.')

    # Run initial CVE job
    _cve_job(registry, pending, gh, llm)

    # Schedule recurring jobs
    poll_interval = config.get('nvd_poll_interval_minutes', 5)
    commit_interval = config.get('commit_poll_interval_minutes', 15)
    summary_time = config.get('daily_summary_time', '23:55')

    schedule.every(poll_interval).minutes.do(_cve_job, registry, pending, gh, llm)
    schedule.every(commit_interval).minutes.do(poll_commits, registry, gh)
    schedule.every().day.at(summary_time).do(_daily_summary_job)

    print(f'[main] Scheduled: CVE every {poll_interval}m, '
          f'commit poll every {commit_interval}m, summary at {summary_time}')

    while True:
        schedule.run_pending()
        time.sleep(1)
