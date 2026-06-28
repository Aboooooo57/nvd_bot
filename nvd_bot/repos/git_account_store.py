from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone

_FILE = 'data/user_git_accounts.json'
_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(_FILE):
        return {}
    try:
        with open(_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    os.makedirs(os.path.dirname(_FILE), exist_ok=True)
    with open(_FILE, 'w') as f:
        json.dump(data, f, indent=2)


class GitAccountStore:
    def list_accounts(self, uid: int) -> list[dict]:
        with _lock:
            accounts = _load().get(str(uid), [])
        return [dict(a, idx=i) for i, a in enumerate(accounts)]

    def add_account(self, uid: int, provider_type: str, base_url: str,
                    token: str, username: str) -> int:
        with _lock:
            data = _load()
            key = str(uid)
            accounts = data.setdefault(key, [])
            entry = {
                'type': provider_type,
                'base_url': base_url,
                'token': token,
                'username': username,
                'connected_at': datetime.now(timezone.utc).isoformat(),
            }
            for i, a in enumerate(accounts):
                if a['type'] == provider_type and a['base_url'] == base_url:
                    accounts[i] = entry
                    _save(data)
                    return i
            accounts.append(entry)
            _save(data)
            return len(accounts) - 1

    def remove_account(self, uid: int, idx: int) -> bool:
        with _lock:
            data = _load()
            accounts = data.get(str(uid), [])
            if 0 <= idx < len(accounts):
                accounts.pop(idx)
                data[str(uid)] = accounts
                _save(data)
                return True
        return False

    def get_account(self, uid: int, idx: int) -> dict | None:
        with _lock:
            accounts = _load().get(str(uid), [])
        if 0 <= idx < len(accounts):
            return dict(accounts[idx], idx=idx)
        return None

    def get_token(self, uid: int, idx: int) -> str | None:
        acc = self.get_account(uid, idx)
        return acc['token'] if acc else None

    def find_account_for_host(self, uid: int, provider_type: str, base_url: str) -> dict | None:
        for acc in self.list_accounts(uid):
            if acc['type'] == provider_type and acc['base_url'] == base_url:
                return acc
        return None
