"""KEV/EPSS enrichment and the immediate-alert escape hatch.

No test here touches the network: every request is stubbed. The most
important cases are the failure ones — enrichment must never be able to
stop an alert.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_sent = []


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


def setup_module():
    os.chdir(tempfile.mkdtemp())
    from nvd_bot import config
    config.load()
    from nvd_bot import main
    main.tgbot.send = lambda text, **kw: (_sent.append(text), None)[1]


def _fresh():
    from nvd_bot import config, main
    for path in (config.KEV_CACHE_FILE, config.EPSS_CACHE_FILE,
                 config.SEEN_CVES_FILE, config.DAILY_ALERTS_FILE,
                 config.POLL_STATE_FILE, config.ISSUE_LEDGER_FILE):
        if os.path.exists(path):
            os.remove(path)
    main._daily_alerts.clear()
    _sent.clear()
    config.set('enrichment_enabled', True)
    config.set('per_cve_alerts', False)
    config.set('immediate_severity', 'CRITICAL')
    config.set('immediate_on_kev', True)
    config.set('min_epss_for_issue', 0.0)


def _stub(monkey_kev=None, monkey_epss=None, fail=False):
    """Point both feeds at canned responses."""
    from nvd_bot.nvd import enrichment

    def fake_get(url, params=None, timeout=None):
        if fail:
            raise OSError('network down')
        if 'cisa.gov' in url:
            return _Resp({'vulnerabilities': [{'cveID': c} for c in (monkey_kev or [])]})
        return _Resp({'data': [{'cve': c, 'epss': str(s), 'percentile': '0.9'}
                               for c, s in (monkey_epss or {}).items()]})

    enrichment.requests.get = fake_get


def _cve(cid, severity, desc='A flaw in django allows RCE'):
    return {'cve': {'id': cid, 'vulnStatus': 'Analyzed',
                    'descriptions': [{'lang': 'en', 'value': desc}],
                    'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': severity}}]}}}


class _Reg:
    def list_repos(self):
        return []


# ── lookups ───────────────────────────────────────────────────────────────────

def test_kev_membership():
    from nvd_bot.nvd import enrichment
    _fresh()
    _stub(monkey_kev=['CVE-2026-1'])
    assert enrichment.is_kev('CVE-2026-1') is True
    assert enrichment.is_kev('CVE-2026-2') is False


def test_epss_score_parsed_and_cached():
    from nvd_bot import config
    from nvd_bot.nvd import enrichment
    _fresh()
    _stub(monkey_epss={'CVE-2026-1': 0.87})
    assert enrichment.epss_scores(['CVE-2026-1'])['CVE-2026-1']['score'] == 0.87
    assert 'CVE-2026-1' in json.load(open(config.EPSS_CACHE_FILE))

    # second call must not re-fetch
    _stub(fail=True)
    assert enrichment.epss_scores(['CVE-2026-1'])['CVE-2026-1']['score'] == 0.87


# ── fail-open ─────────────────────────────────────────────────────────────────

def test_unreachable_feeds_return_none_not_false():
    """None means 'unknown'. Returning False would read as 'not exploited'."""
    from nvd_bot.nvd import enrichment
    _fresh()
    _stub(fail=True)
    assert enrichment.is_kev('CVE-2026-1') is None
    assert enrichment.epss_scores(['CVE-2026-1']) == {}


def test_alerting_continues_when_enrichment_is_down():
    from nvd_bot import main
    _fresh()
    _stub(fail=True)
    main.process_cve(_cve('CVE-2026-9', 'HIGH'), _Reg(), None, None)
    assert len(main._daily_alerts) == 1, 'a feed outage must not drop the CVE'


def test_stale_kev_cache_is_kept_when_refresh_fails():
    from nvd_bot.nvd import enrichment
    _fresh()
    _stub(monkey_kev=['CVE-2026-1'])
    assert enrichment.is_kev('CVE-2026-1') is True
    _stub(fail=True)
    enrichment.refresh_kev(force=True)
    assert enrichment.is_kev('CVE-2026-1') is True, 'stale data beats no data'


def test_empty_kev_response_does_not_wipe_cache():
    from nvd_bot.nvd import enrichment
    _fresh()
    _stub(monkey_kev=['CVE-2026-1'])
    enrichment.refresh_kev(force=True)
    _stub(monkey_kev=[])
    enrichment.refresh_kev(force=True)
    assert enrichment.is_kev('CVE-2026-1') is True


# ── immediate escape hatch ────────────────────────────────────────────────────

def test_critical_breaks_through_the_digest():
    from nvd_bot import main
    _fresh()
    _stub(monkey_kev=[], monkey_epss={})
    main.process_cve(_cve('CVE-2026-3', 'CRITICAL'), _Reg(), None, None)
    assert len(_sent) == 1
    assert 'Urgent CVE Alert' in _sent[0]


def test_high_still_waits_for_the_digest():
    from nvd_bot import main
    _fresh()
    _stub(monkey_kev=[], monkey_epss={})
    main.process_cve(_cve('CVE-2026-4', 'HIGH'), _Reg(), None, None)
    assert _sent == []


def test_kev_breaks_through_even_at_medium():
    """The point of KEV: actively exploited beats nominally severe."""
    from nvd_bot import main
    _fresh()
    _stub(monkey_kev=['CVE-2026-5'], monkey_epss={})
    main.process_cve(_cve('CVE-2026-5', 'MEDIUM'), _Reg(), None, None)
    assert len(_sent) == 1
    assert 'Exploited in the wild' in _sent[0]


def test_immediate_can_be_disabled():
    from nvd_bot import config, main
    _fresh()
    _stub(monkey_kev=['CVE-2026-6'], monkey_epss={})
    config.set('immediate_on_kev', False)
    config.set('immediate_severity', '')
    main.process_cve(_cve('CVE-2026-6', 'CRITICAL'), _Reg(), None, None)
    assert _sent == []


def test_signals_recorded_on_the_daily_alert():
    from nvd_bot import main
    _fresh()
    _stub(monkey_kev=['CVE-2026-7'], monkey_epss={'CVE-2026-7': 0.42})
    main.process_cve(_cve('CVE-2026-7', 'HIGH'), _Reg(), None, None)
    alert = main._daily_alerts[0]
    assert alert['kev'] is True
    assert alert['epss'] == 0.42


def test_epss_filter_is_off_by_default():
    from nvd_bot import config
    _fresh()
    assert config.get('min_epss_for_issue') == 0.0
