"""User-driven noise suppression.

Watchlist keywords match on description text, so a CVE in an unrelated
product routinely matches because its write-up happens to mention your
stack — an Electron app "with full Node.js access" matches `node`. Rather
than making the keyword rules cleverer, let the reader say "not this one"
once and have it stick.

Two levels:

  dismiss  — this specific CVE, never mention it again
  ignore   — this product, don't alert on it again at all

Both are deliberately limited to watchlist-only noise. Neither can suppress
a CVE that actually matches a tracked repo's dependencies: that is the
signal this bot exists to deliver, and it should not be silenceable by a
mis-tap on an unrelated alert.
"""
from __future__ import annotations
import json
import os
import threading

from nvd_bot import config

_lock = threading.Lock()
_MAX_DISMISSED = 500


def _read() -> list[str]:
    if not os.path.exists(config.DISMISSED_CVES_FILE):
        return []
    try:
        with open(config.DISMISSED_CVES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f'[mutes] read error: {e}')
        return []


def _write(ids: list[str]):
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = config.DISMISSED_CVES_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(ids[-_MAX_DISMISSED:], f)
        os.replace(tmp, config.DISMISSED_CVES_FILE)
    except Exception as e:
        print(f'[mutes] write error: {e}')


# ── per-CVE dismissal ─────────────────────────────────────────────────────────

def dismiss_cve(cve_id: str) -> bool:
    with _lock:
        ids = _read()
        if cve_id in ids:
            return False
        ids.append(cve_id)
        _write(ids)
        return True


def is_dismissed(cve_id: str) -> bool:
    with _lock:
        return cve_id in _read()


def dismissed_count() -> int:
    with _lock:
        return len(_read())


# ── per-product ignore ────────────────────────────────────────────────────────

def _normalise(product: str) -> str:
    return (product or '').strip().lower()


def ignore_product(product: str) -> bool:
    product = _normalise(product)
    if not product:
        return False
    ignored = [_normalise(p) for p in config.get('ignored_products', [])]
    if product in ignored:
        return False
    ignored.append(product)
    return config.set('ignored_products', ignored)


def unignore_product(product: str) -> bool:
    product = _normalise(product)
    ignored = [_normalise(p) for p in config.get('ignored_products', [])]
    if product not in ignored:
        return False
    ignored.remove(product)
    return config.set('ignored_products', ignored)


def ignored_products() -> list[str]:
    return [_normalise(p) for p in config.get('ignored_products', [])]


def matched_ignored(packages) -> str | None:
    """Return the first affected product that the user has muted, if any."""
    ignored = set(ignored_products())
    if not ignored:
        return None
    for pkg in (packages or []):
        if _normalise(pkg) in ignored:
            return _normalise(pkg)
    return None
