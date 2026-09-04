"""Guards against filing an issue on someone else's vulnerability.

The defect these pin: the description fallback searched the whole sentence for
a version phrase, so "marker before 1.10.0 ... via the FastAPI upload handler"
recorded fastapi <1.10.0. FastAPI is versioned 0.x, so it sits under virtually
every ceiling NVD publishes — the mispairing matched every install of it and
opened issues on repos that were never affected.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def setup_module():
    os.chdir(tempfile.mkdtemp())
    from nvd_bot import config
    config.load()


def _cve(desc, affected=None, cpe=None):
    cve = {'id': 'CVE-2026-1', 'vulnStatus': 'Analyzed',
           'descriptions': [{'lang': 'en', 'value': desc}],
           'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': 'HIGH'}}]}}
    if affected:
        cve['affected'] = affected
    if cpe:
        cve['configurations'] = [{'nodes': [{'cpeMatch': cpe}]}]
    return {'cve': cve}


def _advisory(package, less_than, start='0'):
    return [{'source': 'gh', 'affectedData': [
        {'packageName': package, 'product': package,
         'versions': [{'version': start, 'lessThan': less_than,
                       'status': 'affected'}]}]}]


def _repo(packages):
    class R:
        id, name, enabled, github_token = 'r', 'me/app', True, None

        def all_packages_flat(self):
            return packages
    return R()


MARKER_CVE = ("marker before 1.10.0 allows arbitrary file write via the FastAPI "
              "upload handler when a crafted filename is supplied.")


# ── the regression ────────────────────────────────────────────────────────────

def test_version_is_not_pinned_onto_a_merely_mentioned_package():
    from nvd_bot.nvd.filter import extract_affected_packages
    got = extract_affected_packages(_cve(MARKER_CVE))
    assert 'fastapi' not in got, f"marker's ceiling attached to fastapi: {got}"


def test_no_issue_is_opened_for_the_mentioned_package():
    from nvd_bot.nvd.filter import extract_affected_packages
    from nvd_bot.matching.matcher import match_cve_to_repos
    item = _cve(MARKER_CVE)
    firm = extract_affected_packages(item, authoritative_only=True)
    matches = match_cve_to_repos(item, [_repo({'fastapi': ('0.115.0', 'requirements.txt')})], firm)
    assert matches == []


def test_prose_derived_package_never_reaches_the_matcher():
    """Even when the prose pairing is correct, a guess must not open an issue."""
    from nvd_bot.nvd.filter import extract_affected_packages
    item = _cve('fastapi before 0.109.1 allows a denial of service.')
    assert extract_affected_packages(item) == {'fastapi': ['<0.109.1']}
    assert extract_affected_packages(item, authoritative_only=True) == {}


# ── the authoritative path still works ────────────────────────────────────────

def test_cna_advisory_gives_the_right_range():
    from nvd_bot.nvd.filter import extract_affected_packages
    item = _cve('ReDoS affecting fastapi.', affected=_advisory('fastapi', '0.109.1'))
    assert extract_affected_packages(item, authoritative_only=True) == {'fastapi': ['<0.109.1']}


def test_true_positive_still_opens_an_issue():
    from nvd_bot.nvd.filter import extract_affected_packages
    from nvd_bot.matching.matcher import match_cve_to_repos
    item = _cve('ReDoS affecting fastapi.', affected=_advisory('fastapi', '0.109.1'))
    firm = extract_affected_packages(item, authoritative_only=True)
    matches = match_cve_to_repos(item, [_repo({'fastapi': ('0.100.0', 'requirements.txt')})], firm)
    assert len(matches) == 1
    assert matches[0].matched_packages == ['fastapi']


def test_patched_version_is_not_matched():
    from nvd_bot.nvd.filter import extract_affected_packages
    from nvd_bot.matching.matcher import match_cve_to_repos
    item = _cve('ReDoS affecting fastapi.', affected=_advisory('fastapi', '0.109.1'))
    firm = extract_affected_packages(item, authoritative_only=True)
    assert match_cve_to_repos(item, [_repo({'fastapi': ('0.115.0', 'requirements.txt')})], firm) == []


def test_each_advisory_package_keeps_its_own_range():
    """The property the prose fallback couldn't provide."""
    from nvd_bot.nvd.filter import extract_affected_packages
    affected = [{'source': 'gh', 'affectedData': [
        {'packageName': 'python-multipart',
         'versions': [{'version': '0', 'lessThan': '0.0.7', 'status': 'affected'}]},
        {'packageName': 'fastapi',
         'versions': [{'version': '0', 'lessThan': '0.109.1', 'status': 'affected'}]}]}]
    got = extract_affected_packages(_cve('multipart ReDoS', affected=affected),
                                    authoritative_only=True)
    assert got == {'python-multipart': ['<0.0.7'], 'fastapi': ['<0.109.1']}


def test_advisory_takes_precedence_over_cpe():
    from nvd_bot.nvd.filter import extract_affected_packages
    item = _cve('fastapi flaw',
                affected=_advisory('fastapi', '0.109.1'),
                cpe=[{'vulnerable': True,
                      'criteria': 'cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:*:*:*',
                      'versionEndExcluding': '9.9.9'}])
    assert extract_affected_packages(item, authoritative_only=True)['fastapi'] == ['<0.109.1']


def test_unaffected_versions_are_ignored():
    from nvd_bot.nvd.filter import extract_affected_packages
    affected = [{'source': 'gh', 'affectedData': [
        {'packageName': 'fastapi',
         'versions': [{'version': '0', 'lessThan': '9.9.9', 'status': 'unaffected'}]}]}]
    assert extract_affected_packages(_cve('x', affected=affected),
                                     authoritative_only=True) == {'fastapi': []}


def test_multiple_ranges_widen_rather_than_contradict():
    """Specs are ANDed downstream; disjoint ranges must not collapse to
    something unsatisfiable and silently stop reporting."""
    from nvd_bot.nvd.filter import extract_affected_packages
    from nvd_bot.matching.matcher import match_cve_to_repos
    affected = [{'source': 'gh', 'affectedData': [
        {'packageName': 'fastapi',
         'versions': [{'version': '0', 'lessThan': '0.100.0', 'status': 'affected'},
                      {'version': '0', 'lessThan': '0.109.1', 'status': 'affected'}]}]}]
    item = _cve('x', affected=affected)
    firm = extract_affected_packages(item, authoritative_only=True)
    assert firm == {'fastapi': ['<0.109.1']}
    assert len(match_cve_to_repos(item, [_repo({'fastapi': ('0.90.0', 'r.txt')})], firm)) == 1


# ── prose fallback, narrowed but still useful ─────────────────────────────────

def test_adjacent_version_is_still_picked_up():
    from nvd_bot.nvd.filter import extract_affected_packages
    got = extract_affected_packages(_cve('django before 4.2.1 allows SQL injection.'))
    assert got == {'django': ['<4.2.1']}


def test_distant_version_is_rejected():
    from nvd_bot.nvd.filter import extract_affected_packages
    got = extract_affected_packages(_cve(
        'A bug fixed before 9.9.9 in some other product also affects users of django '
        'in deployments where debug is on.'))
    assert 'django' not in got
