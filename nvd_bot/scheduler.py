from __future__ import annotations
import time
import schedule
from datetime import datetime, timezone

from nvd_bot import config
from nvd_bot.repos.registry import RepoRegistry
from nvd_bot.repos.github_client import GithubClient
from nvd_bot.repos.scanner import scan_repo, _split_name


def poll_commits(registry: RepoRegistry, gh: GithubClient):
    """Check each tracked repo for new commits; update profile if changed."""
    repos = registry.list_repos()
    if not repos:
        return
    print(f'[scheduler] Polling {len(repos)} repo(s) for new commits…')
    for profile in repos:
        if not profile.enabled:
            continue
        try:
            owner, repo = _split_name(profile.name)
            if not owner:
                continue
            sha = gh.get_latest_commit_sha(owner, repo, token=profile.github_token)
            if sha and sha != profile.last_commit_sha:
                print(f'[scheduler] New commit in {profile.name}: {sha[:8]}')
                # scan_repo() pushes an updated profile.json and sets
                # profile.last_commit_sha to that push's own commit sha —
                # not to `sha` above — so the next poll doesn't mistake the
                # bot's own commit for a fresh upstream change and loop forever.
                scan_repo(profile, gh)
                registry.update_profile(profile)
        except Exception as e:
            print(f'[scheduler] Error polling {profile.name}: {e}')


def start(jobs: list[tuple]):
    """
    jobs: list of (schedule_spec_callable, job_fn)
    e.g. [(lambda fn: schedule.every(5).minutes.do(fn), my_fn), ...]
    """
    for spec, fn in jobs:
        spec(fn)
    print('[scheduler] Running…')
    while True:
        schedule.run_pending()
        time.sleep(1)
