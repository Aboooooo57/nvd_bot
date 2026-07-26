"""Version reporting."""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _reload(**env):
    """Reload the module with a given environment, since the build stamp is
    read at import time."""
    for key in ('GIT_SHA', 'BUILD_DATE'):
        os.environ.pop(key, None)
    os.environ.update(env)
    import nvd_bot.version as ver
    return importlib.reload(ver)


def teardown_module():
    _reload()


def test_version_string_without_a_build_stamp():
    ver = _reload()
    assert ver.version_string() == f'v{ver.__version__}'


def test_version_string_includes_commit_when_stamped():
    ver = _reload(GIT_SHA='b637b40')
    assert ver.version_string() == f'v{ver.__version__} (b637b40)'


def test_unknown_placeholder_is_treated_as_absent():
    """The Dockerfile defaults the arg to 'unknown'; that must not leak into
    the UI as if it were a real sha."""
    ver = _reload(GIT_SHA='unknown', BUILD_DATE='unknown')
    assert ver.version_string() == f'v{ver.__version__}'
    assert 'unknown' not in dict(ver.build_details()).get('Built', '')


def test_build_details_reports_a_missing_commit_honestly():
    ver = _reload()
    assert 'not baked in' in dict(ver.build_details())['Commit']


def test_build_details_includes_date_when_stamped():
    ver = _reload(GIT_SHA='abc1234', BUILD_DATE='2026-07-26T12:00Z')
    rows = dict(ver.build_details())
    assert rows['Commit'] == 'abc1234'
    assert rows['Built'] == '2026-07-26T12:00Z'


def test_dirty_marker_is_preserved():
    """A dirty build must stay visibly dirty — the image doesn't match the
    commit it claims."""
    ver = _reload(GIT_SHA='abc1234-dirty')
    assert ver.version_string().endswith('(abc1234-dirty)')
