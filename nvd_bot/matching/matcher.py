from __future__ import annotations
from dataclasses import dataclass, field
import re

from nvd_bot.repos.profile import RepoProfile
from nvd_bot.nvd.formatter import extract_meta


@dataclass
class MatchResult:
    repo: RepoProfile
    cve_id: str
    severity: str
    matched_packages: list[str] = field(default_factory=list)
    current_versions: dict[str, str] = field(default_factory=dict)  # {pkg: version}
    source_files: dict[str, str] = field(default_factory=dict)      # {pkg: file}
    affected_specs: dict[str, list[str]] = field(default_factory=dict)  # {pkg: [specs]}


def match_cve_to_repos(
    cve_item: dict,
    repos: list[RepoProfile],
    affected_packages: dict[str, list[str]],
) -> list[MatchResult]:
    cve_id, _, severity, _ = extract_meta(cve_item)
    results = []

    if not affected_packages:
        return results

    for repo in repos:
        if not repo.enabled:
            continue
        flat = repo.all_packages_flat()  # {normalized_name: (version, source_file)}
        matched_pkgs = []
        current_versions = {}
        source_files = {}
        affected_specs = {}

        for affected_pkg, specs in affected_packages.items():
            norm_affected = _normalize(affected_pkg)
            # Exact normalized name match only (no fuzzy substring — too noisy)
            if norm_affected in flat:
                ver, src = flat[norm_affected]
                if _is_vulnerable(ver, specs):
                    matched_pkgs.append(affected_pkg)
                    current_versions[affected_pkg] = ver
                    source_files[affected_pkg] = src
                    affected_specs[affected_pkg] = specs

        if matched_pkgs:
            results.append(MatchResult(
                repo=repo,
                cve_id=cve_id,
                severity=severity,
                matched_packages=matched_pkgs,
                current_versions=current_versions,
                source_files=source_files,
                affected_specs=affected_specs,
            ))

    return results


def _normalize(name: str) -> str:
    return re.sub(r'[_\s]', '-', name.lower().split('[')[0].strip())


def _is_vulnerable(current_ver: str, specs: list[str]) -> bool:
    """Return True only when we can confirm the version is in the vulnerable range.

    - No range in the CVE: accept (the name already matched exactly).
    - Range present but installed version unknown: reject (don't claim a match).
    - Range present and version known: compare; unparseable → reject.
    """
    if not specs:
        return True
    if current_ver in ('unknown', ''):
        return False
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
        ss = SpecifierSet(','.join(specs))
        return Version(current_ver) in ss
    except Exception:
        return False
