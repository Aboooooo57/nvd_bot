"""Duplicate-issue prevention."""
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
    for path in (config.ISSUE_LEDGER_FILE, config.SEEN_CVES_FILE,
                 config.DAILY_ALERTS_FILE, config.POLL_STATE_FILE):
        if os.path.exists(path):
            os.remove(path)
    main._daily_alerts.clear()
    _sent.clear()


# ── ledger unit behaviour ─────────────────────────────────────────────────────

def test_record_and_get():
    from nvd_bot.repos.issue_ledger import IssueLedger
    _fresh()
    led = IssueLedger()
    assert led.get('repo-a', 'CVE-1') is None
    led.record('repo-a', 'CVE-1', 'https://github.com/o/r/issues/7', 'HIGH')
    entry = led.get('repo-a', 'CVE-1')
    assert entry['issue_url'].endswith('/7')
    assert entry['severity'] == 'HIGH'


def test_same_cve_different_repos_are_independent():
    from nvd_bot.repos.issue_ledger import IssueLedger
    _fresh()
    led = IssueLedger()
    led.record('repo-a', 'CVE-1', 'url-a', 'HIGH')
    assert led.get('repo-b', 'CVE-1') is None, 'each repo needs its own issue'


def test_forget_repo_clears_only_that_repo():
    from nvd_bot.repos.issue_ledger import IssueLedger
    _fresh()
    led = IssueLedger()
    led.record('repo-a', 'CVE-1', 'url-a', 'HIGH')
    led.record('repo-b', 'CVE-1', 'url-b', 'HIGH')
    led.forget_repo('repo-a')
    assert led.get('repo-a', 'CVE-1') is None
    assert led.get('repo-b', 'CVE-1') is not None


def test_corrupt_ledger_does_not_crash():
    from nvd_bot import config
    from nvd_bot.repos.issue_ledger import IssueLedger
    _fresh()
    with open(config.ISSUE_LEDGER_FILE, 'w') as f:
        f.write('not json at all')
    led = IssueLedger()
    assert led.get('repo-a', 'CVE-1') is None
    led.record('repo-a', 'CVE-1', 'url', 'HIGH')
    assert led.get('repo-a', 'CVE-1') is not None


# ── integration with _handle_match ────────────────────────────────────────────

class _FakeGh:
    def __init__(self):
        self.created = []
        self.comments = []

    def create_issue(self, owner, repo, title, body, labels=None, token=None):
        url = f'https://github.com/{owner}/{repo}/issues/{len(self.created) + 1}'
        self.created.append(url)
        return url

    def comment_on_issue(self, owner, repo, issue_url, body, token=None):
        self.comments.append((issue_url, body))
        return True


class _Repo:
    id = 'repo-a-abc123'
    name = 'owner/repo-a'
    github_token = None


class _Match:
    repo = _Repo()
    matched_packages = ['django']
    current_versions = {'django': '4.0.0'}
    affected_specs = {'django': ['<4.2.1']}
    source_files = {'django': 'requirements.txt'}


def _cve(cid, severity):
    return {'cve': {'id': cid, 'vulnStatus': 'Analyzed',
                    'descriptions': [{'lang': 'en', 'value': 'django flaw'}],
                    'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': severity}}]}}}


def test_first_detection_creates_issue():
    from nvd_bot import main
    _fresh()
    gh = _FakeGh()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'HIGH'), gh)
    assert len(gh.created) == 1
    assert any('Security issue created' in m for m in _sent)


def test_redetection_does_not_create_a_second_issue():
    """The bug this fixes: seen_cves.csv rotates, so a re-detected CVE used
    to open a duplicate issue."""
    from nvd_bot import main
    _fresh()
    gh = _FakeGh()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'HIGH'), gh)
    _sent.clear()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'HIGH'), gh)

    assert len(gh.created) == 1, 'duplicate issue opened'
    assert gh.comments == [], 'unchanged severity should stay silent'
    assert _sent == [], 'and should not re-notify Telegram'


def test_severity_upgrade_comments_instead_of_duplicating():
    from nvd_bot import main
    _fresh()
    gh = _FakeGh()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'MEDIUM'), gh)
    _sent.clear()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'CRITICAL'), gh)

    assert len(gh.created) == 1
    assert len(gh.comments) == 1
    assert 'MEDIUM → CRITICAL' in gh.comments[0][1]
    assert any('Severity raised' in m for m in _sent)


def test_severity_downgrade_is_silent():
    from nvd_bot import main
    _fresh()
    gh = _FakeGh()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'CRITICAL'), gh)
    _sent.clear()
    main._handle_match(_Match(), _cve('CVE-2026-1', 'LOW'), gh)
    assert gh.comments == []
    assert _sent == []


def test_failed_issue_creation_is_not_recorded():
    """A failed create must stay retryable, not be remembered as done."""
    from nvd_bot import main
    from nvd_bot.repos.issue_ledger import IssueLedger
    _fresh()

    class _FailingGh(_FakeGh):
        def create_issue(self, *a, **kw):
            return None

    main._handle_match(_Match(), _cve('CVE-2026-2', 'HIGH'), _FailingGh())
    assert IssueLedger().get('repo-a-abc123', 'CVE-2026-2') is None

    gh = _FakeGh()
    main._handle_match(_Match(), _cve('CVE-2026-2', 'HIGH'), gh)
    assert len(gh.created) == 1, 'retry after failure should still create'
