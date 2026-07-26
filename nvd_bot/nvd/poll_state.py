"""Persistent NVD polling state.

Two things live here, both in data/poll_state.json:

  last_poll_utc — how far the CVE feed has been successfully fetched. Advanced
    only after a poll succeeds, so a failed or timed-out cycle re-covers the
    same window next time instead of losing it.

  pending — CVEs that matched us but arrived without a CVSS score. NVD
    routinely publishes first and scores days later; the feed query is by
    publication date, so without this store those CVEs would never be looked
    at again, however bad they turn out to be.
"""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timedelta, timezone

from nvd_bot import config

_lock = threading.Lock()
_ISO = '%Y-%m-%dT%H:%M:%S'


def _read_unlocked() -> dict:
    if not os.path.exists(config.POLL_STATE_FILE):
        return {}
    try:
        with open(config.POLL_STATE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f'[poll_state] read error: {e}')
        return {}


def _write_unlocked(state: dict):
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = config.POLL_STATE_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, config.POLL_STATE_FILE)
    except Exception as e:
        print(f'[poll_state] write error: {e}')


# ── Poll watermark ────────────────────────────────────────────────────────────

def get_last_poll() -> datetime | None:
    with _lock:
        raw = _read_unlocked().get('last_poll_utc')
    if not raw:
        return None
    try:
        return datetime.strptime(raw, _ISO).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def set_last_poll(when: datetime):
    with _lock:
        state = _read_unlocked()
        state['last_poll_utc'] = when.astimezone(timezone.utc).strftime(_ISO)
        _write_unlocked(state)


def compute_window(now: datetime) -> tuple[datetime, datetime | None]:
    """Return (start, skipped_until).

    start is where this poll should begin. skipped_until is non-None only when
    the gap since the last successful poll exceeded max_catchup_hours: the
    window start is clamped and the caller is expected to make the uncovered
    stretch visible rather than let it vanish quietly.
    """
    last = get_last_poll()
    if last is None:
        lookback = config.get('cve_lookback_minutes', 6)
        return now - timedelta(minutes=lookback), None

    max_catchup = config.get('max_catchup_hours', 24)
    earliest = now - timedelta(hours=max_catchup)
    if last < earliest:
        return earliest, earliest
    return last, None


# ── Pending (unscored) CVEs ───────────────────────────────────────────────────

def add_pending(cve_id: str, first_seen: datetime | None = None):
    stamp = (first_seen or datetime.now(timezone.utc)).astimezone(timezone.utc)
    with _lock:
        state = _read_unlocked()
        pending = state.setdefault('pending', {})
        pending.setdefault(cve_id, stamp.strftime(_ISO))
        _write_unlocked(state)


def list_pending() -> list[str]:
    with _lock:
        return sorted(_read_unlocked().get('pending', {}).keys())


def drop_pending(cve_id: str):
    with _lock:
        state = _read_unlocked()
        if state.get('pending', {}).pop(cve_id, None) is not None:
            _write_unlocked(state)


def prune_pending(retention_days: int) -> list[str]:
    """Drop entries older than retention_days. Returns the dropped ids —
    without this the store grows without bound, since some CVEs are never
    scored at all."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    dropped: list[str] = []
    with _lock:
        state = _read_unlocked()
        pending = state.get('pending', {})
        for cve_id, raw in list(pending.items()):
            try:
                seen = datetime.strptime(raw, _ISO).replace(tzinfo=timezone.utc)
            except Exception:
                dropped.append(cve_id)
                pending.pop(cve_id, None)
                continue
            if seen < cutoff:
                dropped.append(cve_id)
                pending.pop(cve_id, None)
        if dropped:
            _write_unlocked(state)
    return dropped


def pending_count() -> int:
    with _lock:
        return len(_read_unlocked().get('pending', {}))
