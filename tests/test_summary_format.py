"""Digest grouping, ordering, and chunking."""
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
    from nvd_bot import config, main
    for path in (config.DAILY_ALERTS_FILE,):
        if os.path.exists(path):
            os.remove(path)
    main._daily_alerts.clear()
    _sent.clear()


def _alert(cid, sev, repos=None, kev=None, epss=None, keywords=('django',)):
    return {'cve_id': cid, 'severity': sev, 'keywords': list(keywords),
            'message_id': None, 'repos': list(repos or []),
            'kev': kev, 'epss': epss}


# ── grouping ──────────────────────────────────────────────────────────────────

def test_repo_affecting_and_watchlist_only_are_separated():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    msgs = build_daily_summary_message([
        _alert('CVE-1', 'HIGH', repos=['me/api']),
        _alert('CVE-2', 'HIGH'),
    ])
    body = '\n'.join(msgs)
    assert 'Affects your repos' in body
    assert 'Watchlist only' in body
    assert body.index('Affects your repos') < body.index('Watchlist only')


def test_alerts_grouped_under_each_repo():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        _alert('CVE-1', 'HIGH', repos=['me/api']),
        _alert('CVE-2', 'HIGH', repos=['me/web']),
    ]))
    assert 'me/api' in body and 'me/web' in body


def test_cve_affecting_two_repos_is_listed_under_both():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        _alert('CVE-1', 'HIGH', repos=['me/api', 'me/web']),
    ]))
    # count rendered link text, not raw id — the id also appears in each href
    assert body.count('>CVE-1</a>') == 2


def test_header_counts():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    msgs = build_daily_summary_message([
        _alert('CVE-1', 'HIGH', repos=['me/api'], kev=True),
        _alert('CVE-2', 'LOW'),
    ])
    assert '<b>2</b> alert(s)' in msgs[0]
    assert '<b>1</b> affecting your repos' in msgs[0]
    assert '<b>1</b> exploited' in msgs[0]


# ── ordering ──────────────────────────────────────────────────────────────────

def test_kev_sorts_above_higher_severity():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        _alert('CVE-crit', 'CRITICAL'),
        _alert('CVE-kev', 'MEDIUM', kev=True),
    ]))
    assert body.index('CVE-kev') < body.index('CVE-crit'), \
        'confirmed exploitation outranks nominal severity'


def test_severity_then_epss_ordering():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        _alert('CVE-low-epss', 'HIGH', epss=0.01),
        _alert('CVE-high-epss', 'HIGH', epss=0.90),
        _alert('CVE-medium', 'MEDIUM', epss=0.99),
    ]))
    assert body.index('CVE-high-epss') < body.index('CVE-low-epss')
    assert body.index('CVE-low-epss') < body.index('CVE-medium')


def test_signals_rendered():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        _alert('CVE-1', 'HIGH', kev=True, epss=0.87)]))
    assert '⚡KEV' in body
    assert 'EPSS 0.87' in body


def test_missing_signals_render_cleanly():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([_alert('CVE-1', 'HIGH')]))
    assert 'None' not in body
    assert 'EPSS' not in body


# ── chunking ──────────────────────────────────────────────────────────────────

def test_long_digest_is_split_under_the_telegram_limit():
    """A digest over 4096 chars used to fail to send outright — which, with
    per-CVE alerts off, meant losing the day's only message."""
    from nvd_bot.nvd.formatter import build_daily_summary_message, _TELEGRAM_LIMIT
    _fresh()
    alerts = [_alert(f'CVE-2026-{i:05d}', 'HIGH', repos=['me/api'], epss=0.5)
              for i in range(300)]
    msgs = build_daily_summary_message(alerts)
    assert len(msgs) > 1, 'should have split'
    assert all(len(m) <= _TELEGRAM_LIMIT for m in msgs), 'a chunk exceeds the limit'


def test_every_cve_survives_chunking():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    alerts = [_alert(f'CVE-2026-{i:05d}', 'HIGH', repos=['me/api']) for i in range(300)]
    body = '\n'.join(build_daily_summary_message(alerts))
    for i in range(300):
        assert f'CVE-2026-{i:05d}' in body, f'lost CVE {i} while splitting'


def test_short_digest_is_a_single_message():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    assert len(build_daily_summary_message([_alert('CVE-1', 'HIGH')])) == 1


# ── send_summary ──────────────────────────────────────────────────────────────

def test_send_summary_drains():
    from nvd_bot import main
    _fresh()
    main._record_daily_alert(_alert('CVE-1', 'HIGH'))
    assert main.send_summary(drain=True) is True
    assert main._daily_alerts == []


def test_send_summary_peek_keeps_the_queue():
    from nvd_bot import main
    _fresh()
    main._record_daily_alert(_alert('CVE-1', 'HIGH'))
    assert main.send_summary(drain=False) is True
    assert len(main._daily_alerts) == 1, 'peek must not clear the queue'


def test_send_summary_reports_nothing_to_send():
    from nvd_bot import main
    _fresh()
    assert main.send_summary(drain=True) is False
    assert _sent == []


def test_all_chunks_are_sent():
    from nvd_bot import main
    _fresh()
    for i in range(300):
        main._record_daily_alert(_alert(f'CVE-2026-{i:05d}', 'HIGH', repos=['me/api']))
    main.send_summary(drain=True)
    assert len(_sent) > 1


# ── content: what's affected and what the problem is ──────────────────────────

def test_watchlist_entry_shows_affected_product_and_description():
    """The complaint this fixes: a bare CVE id says nothing about the actual
    problem once per-CVE alerts are off."""
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        dict(_alert('CVE-1', 'HIGH'), packages=['webstorm'],
             title='In JetBrains WebStorm before 2026.2 arbitrary code execution was possible'),
    ]))
    assert 'webstorm' in body, 'must say what is affected'
    assert 'arbitrary code execution' in body, 'must say what the problem is'


def test_repo_entry_shows_installed_and_vulnerable_versions():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        dict(_alert('CVE-1', 'CRITICAL', repos=['me/api']),
             repo_packages={'me/api': ['express 4.17.1 — vulnerable: <4.19.2']},
             packages=['express'], title='Prototype pollution in express.'),
    ]))
    assert 'express 4.17.1' in body, 'the installed version is the actionable part'
    assert '4.19.2' in body


def test_repo_detail_preferred_over_generic_package_list():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        dict(_alert('CVE-1', 'HIGH', repos=['me/api']),
             repo_packages={'me/api': ['django 4.0.1 — vulnerable: <4.2.1']},
             packages=['django'], title='SQL injection.'),
    ]))
    assert 'django 4.0.1' in body
    assert body.count('📦') == 1, 'should not print both the detail and the bare name'


def test_description_is_truncated_on_a_word_boundary():
    from nvd_bot import config
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    config.set('summary_description_chars', 40)
    body = '\n'.join(build_daily_summary_message([
        dict(_alert('CVE-1', 'HIGH'),
             title='A very long description that keeps going well past the configured limit'),
    ]))
    assert '…' in body
    assert 'configured' not in body
    assert 'A very long description' in body
    config.set('summary_description_chars', 170)


def test_missing_description_and_packages_render_cleanly():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([_alert('CVE-1', 'HIGH')]))
    assert 'None' not in body
    assert '📦' not in body


def test_html_in_description_is_escaped():
    from nvd_bot.nvd.formatter import build_daily_summary_message
    _fresh()
    body = '\n'.join(build_daily_summary_message([
        dict(_alert('CVE-1', 'HIGH'), title='Fails when <script> is passed to eval()'),
    ]))
    assert '&lt;script&gt;' in body, 'raw tags would break Telegram HTML parsing'


def test_detailed_digest_still_chunks_under_the_limit():
    from nvd_bot.nvd.formatter import build_daily_summary_message, _TELEGRAM_LIMIT
    _fresh()
    alerts = [dict(_alert(f'CVE-2026-{i:05d}', 'HIGH', repos=['me/api']),
                   packages=['django'],
                   repo_packages={'me/api': [f'django 4.0.{i} — vulnerable: <4.2.1']},
                   title='A long description ' * 10)
              for i in range(120)]
    msgs = build_daily_summary_message(alerts)
    assert all(len(m) <= _TELEGRAM_LIMIT for m in msgs)
    body = '\n'.join(msgs)
    for i in range(120):
        assert f'CVE-2026-{i:05d}' in body
