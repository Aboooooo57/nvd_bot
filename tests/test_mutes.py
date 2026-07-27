"""Dismiss / mute suppression.

The load-bearing tests here are the ones asserting what mutes *cannot* do:
suppressing a CVE that actually affects a tracked repo would turn a
convenience button into a way to silently lose the signal the bot exists for.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_sent = []


def setup_module():
    os.chdir(tempfile.mkdtemp())
    from nvd_bot import config
    config.load()
    from nvd_bot import main
    main.tgbot.send = lambda text, reply_markup=None, **kw: (
        _sent.append((text, reply_markup)), None)[1]


def _fresh():
    from nvd_bot import config, main
    for path in (config.DISMISSED_CVES_FILE, config.SEEN_CVES_FILE,
                 config.DAILY_ALERTS_FILE, config.POLL_STATE_FILE,
                 config.ISSUE_LEDGER_FILE):
        if os.path.exists(path):
            os.remove(path)
    main._daily_alerts.clear()
    _sent.clear()
    config.set('ignored_products', [])
    config.set('per_cve_alerts', True)


def _cve(cid, severity='HIGH', desc='A flaw in django allows RCE', product=None):
    item = {'cve': {'id': cid, 'vulnStatus': 'Analyzed',
                    'descriptions': [{'lang': 'en', 'value': desc}],
                    'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': severity}}]}}}
    if product:
        item['cve']['configurations'] = [{'nodes': [{'cpeMatch': [
            {'vulnerable': True,
             'criteria': f'cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*',
             'versionEndExcluding': '9.9'}]}]}]
    return item


class _Reg:
    def list_repos(self):
        return []


# ── store behaviour ───────────────────────────────────────────────────────────

def test_dismiss_and_query():
    from nvd_bot.nvd import mutes
    _fresh()
    assert mutes.is_dismissed('CVE-1') is False
    assert mutes.dismiss_cve('CVE-1') is True
    assert mutes.is_dismissed('CVE-1') is True
    assert mutes.dismiss_cve('CVE-1') is False, 'second dismiss is a no-op'


def test_ignore_product_is_case_insensitive():
    from nvd_bot.nvd import mutes
    _fresh()
    mutes.ignore_product('SiYuan')
    assert mutes.ignored_products() == ['siyuan']
    assert mutes.matched_ignored(['siyuan']) == 'siyuan'
    assert mutes.matched_ignored(['SIYUAN']) == 'siyuan'


def test_unignore():
    from nvd_bot.nvd import mutes
    _fresh()
    mutes.ignore_product('siyuan')
    assert mutes.unignore_product('siyuan') is True
    assert mutes.ignored_products() == []
    assert mutes.unignore_product('siyuan') is False


def test_matched_ignored_returns_none_when_nothing_muted():
    from nvd_bot.nvd import mutes
    _fresh()
    assert mutes.matched_ignored(['django', 'flask']) is None


# ── pipeline suppression ──────────────────────────────────────────────────────

def test_dismissed_cve_is_not_alerted_again():
    from nvd_bot import main
    from nvd_bot.nvd import mutes
    _fresh()
    mutes.dismiss_cve('CVE-2026-1')
    main.process_cve(_cve('CVE-2026-1'), _Reg(), None, None)
    assert _sent == []
    assert main._daily_alerts == []


def test_muted_product_is_not_alerted():
    from nvd_bot import main
    from nvd_bot.nvd import mutes
    _fresh()
    mutes.ignore_product('siyuan')
    main.process_cve(
        _cve('CVE-2026-2', desc='SiYuan desktop XSS with full Node.js access',
             product='siyuan'),
        _Reg(), None, None)
    assert _sent == []
    assert main._daily_alerts == []


def test_unmuted_product_still_alerts():
    from nvd_bot import main
    from nvd_bot.nvd import mutes
    _fresh()
    mutes.ignore_product('siyuan')
    mutes.unignore_product('siyuan')
    main.process_cve(
        _cve('CVE-2026-3', desc='SiYuan desktop XSS with full Node.js access',
             product='siyuan'),
        _Reg(), None, None)
    assert len(_sent) == 1


def test_muting_one_product_does_not_silence_others():
    from nvd_bot import main
    from nvd_bot.nvd import mutes
    _fresh()
    mutes.ignore_product('siyuan')
    main.process_cve(_cve('CVE-2026-4', desc='django SQL injection', product='django'),
                     _Reg(), None, None)
    assert len(_sent) == 1, 'unrelated CVEs must still come through'


# ── the limits that matter ────────────────────────────────────────────────────

class _Repo:
    id = 'repo-a'
    name = 'me/api'
    github_token = None


class _Match:
    repo = _Repo()
    matched_packages = ['siyuan']
    current_versions = {'siyuan': '3.7.0'}
    affected_specs = {'siyuan': ['<9.9']}
    source_files = {'siyuan': 'package.json'}


class _MatchingReg:
    def list_repos(self):
        return [_Repo()]


def _force_match(monkey):
    from nvd_bot import main
    main.match_cve_to_repos = monkey


def test_mute_cannot_suppress_a_repo_match():
    """A muted product that turns up as a real dependency is still reported."""
    from nvd_bot import main
    from nvd_bot.nvd import mutes
    _fresh()
    original, original_handle = main.match_cve_to_repos, main._handle_match
    try:
        _force_match(lambda item, repos, affected: [_Match()])
        mutes.ignore_product('siyuan')
        main._handle_match = lambda *a, **k: None  # don't hit GitHub
        main.process_cve(_cve('CVE-2026-5', product='siyuan'), _MatchingReg(), None, None)
        assert len(main._daily_alerts) == 1, 'repo match must survive the mute'
    finally:
        main.match_cve_to_repos, main._handle_match = original, original_handle


def test_dismiss_cannot_suppress_a_repo_match():
    from nvd_bot import main
    from nvd_bot.nvd import mutes
    _fresh()
    original, original_handle = main.match_cve_to_repos, main._handle_match
    try:
        _force_match(lambda item, repos, affected: [_Match()])
        mutes.dismiss_cve('CVE-2026-6')
        main._handle_match = lambda *a, **k: None
        main.process_cve(_cve('CVE-2026-6', product='siyuan'), _MatchingReg(), None, None)
        assert len(main._daily_alerts) == 1, 'repo match must survive the dismissal'
    finally:
        main.match_cve_to_repos, main._handle_match = original, original_handle


# ── digest removal ────────────────────────────────────────────────────────────

def test_remove_daily_alert_drops_only_that_cve():
    from nvd_bot import main
    _fresh()
    main.process_cve(_cve('CVE-2026-7'), _Reg(), None, None)
    main.process_cve(_cve('CVE-2026-8'), _Reg(), None, None)
    assert main.remove_daily_alert('CVE-2026-7') is True
    assert [a['cve_id'] for a in main._daily_alerts] == ['CVE-2026-8']
    assert main.remove_daily_alert('CVE-2026-7') is False


# ── keyboard ──────────────────────────────────────────────────────────────────

def test_keyboard_offers_dismiss_and_mute():
    from nvd_bot.bot.callbacks.cve import build_keyboard
    kb = build_keyboard('CVE-2026-9', ['siyuan', 'node'])
    data = [b.callback_data for row in kb.keyboard for b in row]
    assert 'cve:d:CVE-2026-9' in data
    assert 'cve:m:siyuan' in data


def test_keyboard_skips_products_that_overflow_callback_data():
    """Telegram rejects callback_data over 64 bytes — a too-long product name
    must be dropped, not sent and silently rejected."""
    from nvd_bot.bot.callbacks.cve import build_keyboard
    kb = build_keyboard('CVE-2026-9', ['x' * 200])
    data = [b.callback_data for row in kb.keyboard for b in row]
    assert data == ['cve:d:CVE-2026-9']
    assert all(len(d.encode()) <= 64 for d in data)


def test_alerts_carry_a_keyboard_when_there_is_no_repo_match():
    from nvd_bot import main
    _fresh()
    main.process_cve(_cve('CVE-2026-10'), _Reg(), None, None)
    _, markup = _sent[0]
    assert markup is not None, 'watchlist noise should be dismissible'
