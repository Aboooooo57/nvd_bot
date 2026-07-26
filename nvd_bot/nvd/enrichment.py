"""Exploitation signals from CISA KEV and FIRST EPSS.

CVSS says how bad a vulnerability would be if exploited. It says nothing about
whether anyone is exploiting it, which is why filtering on severity alone
produces so much noise. Two external feeds close that gap:

  KEV   — CISA's Known Exploited Vulnerabilities catalogue. Membership means
          confirmed in-the-wild exploitation. Small (~1.4k entries), fetched
          whole, cached to disk.

  EPSS  — FIRST's probability that a CVE will be exploited in the next 30
          days, 0..1. Fetched per-CVE (batched) and cached with a TTL.

Everything here fails open: if a feed is unreachable the lookups return None
and the pipeline behaves exactly as it did before enrichment existed. A CISA
outage must never be able to stop your alerts.
"""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timedelta, timezone

import requests

from nvd_bot import config

_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
_EPSS_URL = 'https://api.first.org/data/v1/epss'
_TIMEOUT = 20
_EPSS_BATCH = 100  # the API accepts a comma-separated list; keep URLs sane

_lock = threading.Lock()
_ISO = '%Y-%m-%dT%H:%M:%S'


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f'[enrich] read error {path}: {e}')
        return {}


def _write_json(path: str, data: dict):
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception as e:
        print(f'[enrich] write error {path}: {e}')


def _age_hours(stamp: str | None) -> float:
    if not stamp:
        return float('inf')
    try:
        then = datetime.strptime(stamp, _ISO).replace(tzinfo=timezone.utc)
    except Exception:
        return float('inf')
    return (_now() - then).total_seconds() / 3600


# ── KEV ───────────────────────────────────────────────────────────────────────

def refresh_kev(force: bool = False) -> bool:
    """Re-download the KEV catalogue if the cache is stale. Returns True if
    the cache is usable afterwards (fresh or still-valid stale copy)."""
    with _lock:
        cache = _read_json(config.KEV_CACHE_FILE)
        max_age = config.get('kev_refresh_hours', 24)
        if not force and _age_hours(cache.get('fetched_at')) < max_age:
            return True

    try:
        r = requests.get(_KEV_URL, timeout=_TIMEOUT)
        if r.status_code != 200:
            print(f'[enrich] KEV fetch failed: {r.status_code}')
            return bool(cache.get('cve_ids'))
        payload = r.json()
        ids = [v.get('cveID') for v in payload.get('vulnerabilities', []) if v.get('cveID')]
        if not ids:
            print('[enrich] KEV response contained no entries — keeping old cache')
            return bool(cache.get('cve_ids'))
        with _lock:
            _write_json(config.KEV_CACHE_FILE, {
                'fetched_at': _now().strftime(_ISO),
                'cve_ids': sorted(ids),
            })
        print(f'[enrich] KEV cache refreshed: {len(ids)} entries')
        return True
    except Exception as e:
        # Stale data beats no data — an outage shouldn't blind the bot.
        print(f'[enrich] KEV fetch error: {e} — using cached copy if present')
        return bool(cache.get('cve_ids'))


def is_kev(cve_id: str) -> bool | None:
    """True/False if the catalogue is available, None if it isn't."""
    if not config.get('enrichment_enabled', True):
        return None
    refresh_kev()
    with _lock:
        cache = _read_json(config.KEV_CACHE_FILE)
    ids = cache.get('cve_ids')
    if not ids:
        return None
    return cve_id in set(ids)


def kev_cache_age_hours() -> float:
    with _lock:
        return _age_hours(_read_json(config.KEV_CACHE_FILE).get('fetched_at'))


# ── EPSS ──────────────────────────────────────────────────────────────────────

def _cached_epss(cve_ids: list[str]) -> tuple[dict, list[str]]:
    """Split ids into {id: entry} already cached and fresh, plus those needing
    a fetch."""
    ttl = config.get('epss_cache_hours', 24)
    with _lock:
        cache = _read_json(config.EPSS_CACHE_FILE)
    hits, misses = {}, []
    for cid in cve_ids:
        entry = cache.get(cid)
        if entry and _age_hours(entry.get('fetched_at')) < ttl:
            hits[cid] = entry
        else:
            misses.append(cid)
    return hits, misses


def epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """{cve_id: {'score': float, 'percentile': float}} for whatever could be
    resolved. Missing ids simply aren't in the result."""
    if not cve_ids or not config.get('enrichment_enabled', True):
        return {}

    hits, misses = _cached_epss(cve_ids)
    result = {cid: {'score': e.get('score'), 'percentile': e.get('percentile')}
              for cid, e in hits.items()}
    if not misses:
        return result

    fetched: dict[str, dict] = {}
    for i in range(0, len(misses), _EPSS_BATCH):
        chunk = misses[i:i + _EPSS_BATCH]
        try:
            r = requests.get(_EPSS_URL, params={'cve': ','.join(chunk)},
                             timeout=_TIMEOUT)
            if r.status_code != 200:
                print(f'[enrich] EPSS fetch failed: {r.status_code}')
                continue
            for row in r.json().get('data', []):
                cid = row.get('cve')
                if not cid:
                    continue
                try:
                    fetched[cid] = {
                        'score': float(row.get('epss', 0)),
                        'percentile': float(row.get('percentile', 0)),
                    }
                except (TypeError, ValueError):
                    continue
        except Exception as e:
            print(f'[enrich] EPSS fetch error: {e}')
            continue

    if fetched:
        stamp = _now().strftime(_ISO)
        with _lock:
            cache = _read_json(config.EPSS_CACHE_FILE)
            for cid, vals in fetched.items():
                cache[cid] = {**vals, 'fetched_at': stamp}
            _write_json(config.EPSS_CACHE_FILE, cache)
        result.update(fetched)

    return result


def enrich(cve_id: str) -> dict:
    """Exploitation signals for one CVE. Keys are always present; values are
    None when the corresponding feed couldn't answer."""
    scores = epss_scores([cve_id])
    entry = scores.get(cve_id) or {}
    return {
        'kev': is_kev(cve_id),
        'epss': entry.get('score'),
        'epss_percentile': entry.get('percentile'),
    }


def format_signals(enrichment: dict) -> str:
    """Compact human-readable tag, e.g. '⚡KEV  EPSS 0.87'. Empty when
    nothing is known."""
    parts = []
    if enrichment.get('kev'):
        parts.append('⚡KEV')
    epss = enrichment.get('epss')
    if epss is not None:
        parts.append(f'EPSS {epss:.3f}')
    return '  '.join(parts)
