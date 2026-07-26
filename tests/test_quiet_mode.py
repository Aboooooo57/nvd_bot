"""Per-CVE alerts are opt-in; the daily summary is the primary channel."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_sent = []


class _FakeMsg:
    message_id = 999


def setup_module():
    os.chdir(tempfile.mkdtemp())
    from nvd_bot import config
    config.load()
    from nvd_bot import main
    main.tgbot.send = lambda text, **kw: (_sent.append(text), _FakeMsg())[1]


def _fresh():
    from nvd_bot import config
    from nvd_bot import main
    for path in (config.POLL_STATE_FILE, config.DAILY_ALERTS_FILE,
                 config.SEEN_CVES_FILE):
        if os.path.exists(path):
            os.remove(path)
    main._daily_alerts.clear()
    _sent.clear()
    config.set('per_cve_alerts', False)


def _cve(cid, severity, desc):
    return {'cve': {'id': cid, 'vulnStatus': 'Analyzed',
                    'descriptions': [{'lang': 'en', 'value': desc}],
                    'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': severity}}]}}}


class _Reg:
    def list_repos(self):
        return []


def test_default_is_quiet():
    from nvd_bot import config
    _fresh()
    assert config.get('per_cve_alerts') is False


def test_matching_cve_is_recorded_but_not_announced():
    from nvd_bot import main
    _fresh()
    main.process_cve(_cve('CVE-2026-1111', 'HIGH', 'A flaw in django allows RCE'),
                     _Reg(), None, None)
    assert _sent == [], 'nothing should be posted for an individual CVE'
    assert len(main._daily_alerts) == 1
    assert main._daily_alerts[0]['keywords'] == ['django']
    assert main._daily_alerts[0]['message_id'] is None


def test_alerts_survive_a_restart():
    from nvd_bot import config, main
    _fresh()
    main.process_cve(_cve('CVE-2026-1111', 'HIGH', 'django RCE'), _Reg(), None, None)
    assert json.load(open(config.DAILY_ALERTS_FILE))[0]['cve_id'] == 'CVE-2026-1111'

    main._daily_alerts.clear()                      # simulate process restart
    main._daily_alerts.extend(main._load_daily_alerts())
    assert len(main._daily_alerts) == 1


def test_irrelevant_cve_is_ignored_entirely():
    from nvd_bot import main
    _fresh()
    main.process_cve(_cve('CVE-2026-2222', 'LOW', 'Bug in an unrelated product'),
                     _Reg(), None, None)
    assert _sent == []
    assert main._daily_alerts == []


def test_summary_sends_drains_and_links_to_nvd():
    from nvd_bot import config, main
    _fresh()
    main.process_cve(_cve('CVE-2026-1111', 'HIGH', 'django RCE'), _Reg(), None, None)
    main._daily_summary_job()

    assert len(_sent) == 1
    assert 'Daily CVE Summary' in _sent[0]
    # no per-CVE message exists to deep-link to, so it must fall back to NVD
    assert 'nvd.nist.gov/vuln/detail/CVE-2026-1111' in _sent[0]
    assert 't.me/c/' not in _sent[0]
    assert main._daily_alerts == []
    assert json.load(open(config.DAILY_ALERTS_FILE)) == []


def test_empty_summary_sends_nothing():
    from nvd_bot import main
    _fresh()
    main._daily_summary_job()
    assert _sent == []


def test_opting_back_in_restores_per_cve_alerts():
    from nvd_bot import config, main
    _fresh()
    config.set('per_cve_alerts', True)
    main.process_cve(_cve('CVE-2026-3333', 'CRITICAL', 'flask path traversal'),
                     _Reg(), None, None)
    assert len(_sent) == 1
    assert 'New CVE Alert' in _sent[0]
    assert main._daily_alerts[0]['message_id'] == 999, 'deep link needs the id'
