"""Record of which (repo, CVE) pairs already have a GitHub issue.

seen_cves.csv cannot serve this purpose: it rotates at seen_cve_limit and
stores every CVE observed, relevant or not, so at NVD's real volume it holds
roughly a week. A CVE evicted from it and re-detected would open a second
issue on the same repo for the same vulnerability.

The ledger is keyed by repo *id* rather than name so that renaming a repo
upstream doesn't resurrect issues that already exist.
"""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone

from nvd_bot import config


class IssueLedger:
    def __init__(self, path: str | None = None):
        self._path = path or config.ISSUE_LEDGER_FILE
        self._lock = threading.Lock()

    def _key(self, repo_id: str, cve_id: str) -> str:
        return f'{repo_id}:{cve_id}'

    def _read_unlocked(self) -> dict:
        if not os.path.exists(self._path):
            return {}
        try:
            with open(self._path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception as e:
            print(f'[ledger] read error: {e}')
            return {}

    def _write_unlocked(self, data: dict):
        try:
            os.makedirs(os.path.dirname(self._path) or '.', exist_ok=True)
            tmp = self._path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self._path)
        except Exception as e:
            print(f'[ledger] write error: {e}')

    def get(self, repo_id: str, cve_id: str) -> dict | None:
        with self._lock:
            return self._read_unlocked().get(self._key(repo_id, cve_id))

    def record(self, repo_id: str, cve_id: str, issue_url: str, severity: str):
        with self._lock:
            data = self._read_unlocked()
            data[self._key(repo_id, cve_id)] = {
                'issue_url': issue_url,
                'severity': severity,
                'created_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S'),
            }
            self._write_unlocked(data)

    def update_severity(self, repo_id: str, cve_id: str, severity: str):
        with self._lock:
            data = self._read_unlocked()
            entry = data.get(self._key(repo_id, cve_id))
            if entry:
                entry['severity'] = severity
                self._write_unlocked(data)

    def forget_repo(self, repo_id: str):
        """Drop every entry for a repo — called when it stops being tracked,
        so re-adding it later starts clean."""
        with self._lock:
            data = self._read_unlocked()
            prefix = f'{repo_id}:'
            remaining = {k: v for k, v in data.items() if not k.startswith(prefix)}
            if len(remaining) != len(data):
                self._write_unlocked(remaining)

    def count(self) -> int:
        with self._lock:
            return len(self._read_unlocked())
