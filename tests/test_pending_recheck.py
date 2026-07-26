"""Unscored CVEs get re-checked once NVD assigns a score."""
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
    main.tgbot.send = lambda text, **kw: (_sent.append(text), None)[1]


def _fresh():
    from nvd_bot import config
    from nvd_bot import main
    for path in (config.POLL_STATE_FILE, config.DAILY_ALERTS_FILE,
                 config.SEEN_CVES_FILE):
        if os.path.exists(path):
            os.remove(path)
    main._daily_alerts.clear()
    _sent.clear()


def _cve(cid, severity, desc='A flaw in django allows RCE'):
    metrics = {}
    if severity is not None:
        metrics = {'cvssMetricV31': [{'cvssData': {'baseSeverity': severity}}]}
    return {'cve': {'id': cid, 'vulnStatus': 'Awaiting Analysis',
                    'descriptions': [{'lang': 'en', 'value': desc}],
                    'metrics': metrics}}


class _Reg:
    def list_repos(self):
        return []


def test_unscored_cve_is_queued_for_recheck():
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()
    main.process_cve(_cve('CVE-2026-1', None), _Reg(), None, None)
    assert poll_state.list_pending() == ['CVE-2026-1']
    assert main._daily_alerts[0]['severity'] == 'PENDING'


def test_scored_cve_is_not_queued():
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()
    main.process_cve(_cve('CVE-2026-2', 'HIGH'), _Reg(), None, None)
    assert poll_state.list_pending() == []


def test_recheck_upgrades_severity_without_duplicating_summary_entry():
    """The regression this guards: re-evaluating must replace the PENDING
    entry, not add a second line for the same CVE."""
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()

    main.process_cve(_cve('CVE-2026-3', None), _Reg(), None, None)
    assert len(main._daily_alerts) == 1

    main.get_cve_by_id = lambda cid: _cve(cid, 'CRITICAL')
    main._recheck_pending_job(_Reg(), None, None)

    assert len(main._daily_alerts) == 1, 'CVE listed twice in the summary'
    assert main._daily_alerts[0]['severity'] == 'CRITICAL'
    assert poll_state.list_pending() == [], 'should leave the pending list'


def test_recheck_leaves_still_unscored_cve_pending():
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()
    main.process_cve(_cve('CVE-2026-4', None), _Reg(), None, None)

    main.get_cve_by_id = lambda cid: _cve(cid, None)
    main._recheck_pending_job(_Reg(), None, None)
    assert poll_state.list_pending() == ['CVE-2026-4']


def test_recheck_survives_fetch_failure():
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()
    main.process_cve(_cve('CVE-2026-5', None), _Reg(), None, None)

    main.get_cve_by_id = lambda cid: None  # NVD unreachable
    main._recheck_pending_job(_Reg(), None, None)
    assert poll_state.list_pending() == ['CVE-2026-5'], 'must be retried, not dropped'


def test_recheck_does_not_duplicate_seen_csv_rows():
    from nvd_bot import main
    _fresh()
    main.process_cve(_cve('CVE-2026-6', None), _Reg(), None, None)
    main.get_cve_by_id = lambda cid: _cve(cid, 'HIGH')
    main._recheck_pending_job(_Reg(), None, None)

    with open(main.config.SEEN_CVES_FILE) as f:
        rows = [l for l in f.read().splitlines() if 'CVE-2026-6' in l]
    assert len(rows) == 1


def test_aged_out_pending_is_dropped():
    from datetime import datetime, timedelta, timezone
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()
    poll_state.add_pending(
        'CVE-2026-7',
        first_seen=datetime.now(timezone.utc) - timedelta(days=30))
    main.get_cve_by_id = lambda cid: _cve(cid, 'HIGH')
    main._recheck_pending_job(_Reg(), None, None)
    assert poll_state.list_pending() == []


def test_cve_that_stops_matching_leaves_pending():
    """Description rewritten so it no longer hits the watchlist — it should
    not sit in the pending list forever."""
    from nvd_bot import main
    from nvd_bot.nvd import poll_state
    _fresh()
    main.process_cve(_cve('CVE-2026-8', None), _Reg(), None, None)
    main.get_cve_by_id = lambda cid: _cve(cid, 'HIGH', desc='Unrelated product bug')
    main._recheck_pending_job(_Reg(), None, None)
    assert poll_state.list_pending() == []
