from __future__ import annotations
import json
import os
import uuid
import threading
from dataclasses import dataclass, field
from typing import Optional
from nvd_bot import config


@dataclass
class PendingFix:
    fix_id: str
    cve_id: str
    repo_id: str
    repo_name: str
    file_path: str
    original_content: str
    fixed_content: str
    explanation: str
    fix_type: str                        # "version_bump" | "code_patch"
    status: str = 'pending'              # pending | accepted | denied | applied | failed
    created_at: str = ''
    pr_url: Optional[str] = None
    telegram_message_id: Optional[int] = None
    severity: str = 'UNKNOWN'

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, data: dict) -> PendingFix:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


class PendingFixStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._path = config.PENDING_FIXES_FILE

    def _load(self) -> list[PendingFix]:
        if not os.path.exists(self._path):
            return []
        try:
            with open(self._path, 'r') as f:
                return [PendingFix.from_dict(d) for d in json.load(f)]
        except Exception as e:
            print(f'[pending] Load error: {e}')
            return []

    def _save(self, fixes: list[PendingFix]):
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, 'w') as f:
            json.dump([fx.to_dict() for fx in fixes], f, indent=2)

    def add(self, fix: PendingFix) -> str:
        if not fix.fix_id:
            fix.fix_id = _short_id()
        with self._lock:
            fixes = self._load()
            fixes.append(fix)
            self._save(fixes)
        return fix.fix_id

    def get(self, fix_id: str) -> PendingFix | None:
        with self._lock:
            for fx in self._load():
                if fx.fix_id == fix_id:
                    return fx
        return None

    def update_status(self, fix_id: str, status: str,
                       pr_url: str | None = None,
                       telegram_message_id: int | None = None):
        with self._lock:
            fixes = self._load()
            for fx in fixes:
                if fx.fix_id == fix_id:
                    fx.status = status
                    if pr_url is not None:
                        fx.pr_url = pr_url
                    if telegram_message_id is not None:
                        fx.telegram_message_id = telegram_message_id
            self._save(fixes)

    def list_pending(self) -> list[PendingFix]:
        with self._lock:
            return [fx for fx in self._load() if fx.status == 'pending']

    def list_all(self) -> list[PendingFix]:
        with self._lock:
            return self._load()
