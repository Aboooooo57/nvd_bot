import os
import json
import threading

# ── Secrets from environment (never in config.json) ──────────────────────────
TELEGRAM_BOT_TOKEN: str = os.getenv('TELEGRAM_BOT_TOKEN', '')
CHAT_ID: str = os.getenv('CHAT_ID', '')
NVD_API_KEY: str | None = os.getenv('NVD_API_KEY')
GITHUB_TOKEN: str | None = os.getenv('GITHUB_TOKEN')
OPENROUTER_API_KEY: str | None = os.getenv('OPENROUTER_API_KEY')
GEMINI_API_KEY: str | None = os.getenv('GEMINI_API_KEY')
LITELLM_API_KEY: str | None = os.getenv('LITELLM_API_KEY')
LITELLM_BASE_URL: str | None = os.getenv('LITELLM_BASE_URL')
GITHUB_OAUTH_CLIENT_ID: str | None = os.getenv('GITHUB_OAUTH_CLIENT_ID')
GITHUB_OAUTH_CLIENT_SECRET: str | None = os.getenv('GITHUB_OAUTH_CLIENT_SECRET')
_owner_raw = os.getenv('TELEGRAM_OWNER_ID', '')
TELEGRAM_OWNER_ID: int | None = int(_owner_raw) if _owner_raw.strip().isdigit() else None

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_DIR = 'data'
SEEN_CVES_FILE = 'data/seen_cves.csv'
DAILY_ALERTS_FILE = 'data/daily_alerts.json'
POLL_STATE_FILE = 'data/poll_state.json'
ISSUE_LEDGER_FILE = 'data/issue_ledger.json'
KEV_CACHE_FILE = 'data/kev.json'
EPSS_CACHE_FILE = 'data/epss.json'
REPOS_DIR = 'data/repos'
REPO_REGISTRY_FILE = 'data/repos/registry.json'
CONFIG_FILE = 'data/config.json'

# ── Defaults (written to config.json on first run) ────────────────────────────
_DEFAULTS: dict = {
    'nvd_poll_interval_minutes': 5,
    'commit_poll_interval_minutes': 15,
    'daily_summary_time': '23:55',
    # When False (default) the bot stays quiet on individual CVEs — you only
    # hear from it once a day via the summary, plus immediately whenever a
    # security issue is opened on one of your repos. Set True to get a
    # per-CVE alert message again.
    'per_cve_alerts': False,
    # Escape hatch from the digest: these go out the moment they're seen, even
    # with per_cve_alerts off, so an actively-exploited flaw doesn't sit
    # unread until the nightly summary.
    'immediate_severity': 'CRITICAL',
    'immediate_on_kev': True,
    'severity_threshold': 'MEDIUM',
    # KEV (confirmed exploitation) and EPSS (probability of exploitation)
    # annotate and rank CVEs. min_epss_for_issue is a filter and ships off:
    # raise it only once you've watched real scores for a while, since
    # anything below it is dropped without trace.
    'enrichment_enabled': True,
    'kev_refresh_hours': 24,
    'epss_cache_hours': 24,
    'min_epss_for_issue': 0.0,
    'cve_lookback_minutes': 6,
    # Ceiling on how far back a single catch-up poll will reach after downtime.
    # NVD rejects windows over 120 days, and an unbounded query after a long
    # outage would be enormous — past this, the gap is reported instead.
    'max_catchup_hours': 24,
    # NVD often publishes a CVE before scoring it. Unscored CVEs that matched
    # us are re-checked daily until they get a score or age out.
    'pending_recheck_time': '04:00',
    'pending_retention_days': 14,
    'seen_cve_limit': 1000,
    'llm_provider': 'openrouter',
    'llm_model': 'gemini-3.5-flash',
    'llm_max_tokens': 2000,
    'profile_file_path': '.nvd_bot/profile.json',
    'watchlist': ['python', 'node', 'linux', 'ubuntu', 'debian', 'fastapi', 'django', 'flask', 'express', 'spring'],
    'allowed_user_ids': [],
}

_config: dict = {}
_lock = threading.Lock()


def _ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(REPOS_DIR, exist_ok=True)


def load():
    """Load config.json, creating it with defaults if missing."""
    global _config
    _ensure_dirs()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                on_disk = json.load(f)
            # Merge: defaults fill in any missing keys added in future versions
            merged = {**_DEFAULTS, **on_disk}
            with _lock:
                _config = merged
            return
        except Exception as e:
            print(f'[config] Failed to read {CONFIG_FILE}: {e} — using defaults')
    with _lock:
        _config = dict(_DEFAULTS)
    _save_unlocked()


def _save_unlocked():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(_config, f, indent=2)


def get(key: str, default=None):
    with _lock:
        return _config.get(key, default)


def set(key: str, value) -> bool:
    """Update a config key, persist to disk, return True on success."""
    with _lock:
        _config[key] = value
        try:
            _save_unlocked()
            return True
        except Exception as e:
            print(f'[config] Save failed: {e}')
            return False


def all_settings() -> dict:
    with _lock:
        return dict(_config)


def add_watchlist_keyword(word: str) -> bool:
    with _lock:
        kw = _config.setdefault('watchlist', [])
        if word.lower() not in [k.lower() for k in kw]:
            kw.append(word.lower())
            try:
                _save_unlocked()
                return True
            except Exception:
                return False
    return False


def remove_watchlist_keyword(word: str) -> bool:
    with _lock:
        kw = _config.get('watchlist', [])
        lower = [k.lower() for k in kw]
        if word.lower() in lower:
            idx = lower.index(word.lower())
            kw.pop(idx)
            _config['watchlist'] = kw
            try:
                _save_unlocked()
                return True
            except Exception:
                return False
    return False


def add_allowed_user(uid: int) -> bool:
    with _lock:
        users = _config.setdefault('allowed_user_ids', [])
        if uid not in users:
            users.append(uid)
            try:
                _save_unlocked()
                return True
            except Exception:
                return False
    return False


def remove_allowed_user(uid: int) -> bool:
    with _lock:
        users = _config.get('allowed_user_ids', [])
        if uid in users:
            users.remove(uid)
            _config['allowed_user_ids'] = users
            try:
                _save_unlocked()
                return True
            except Exception:
                return False
    return False
