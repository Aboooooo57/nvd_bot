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
            # Direct name match
            if norm_affected in flat:
                ver, src = flat[norm_affected]
                if _is_vulnerable(ver, specs):
                    matched_pkgs.append(affected_pkg)
                    current_versions[affected_pkg] = ver
                    source_files[affected_pkg] = src
                    affected_specs[affected_pkg] = specs
                continue
            # Fuzzy: check if any repo package name contains the affected name
            for repo_pkg, (ver, src) in flat.items():
                if norm_affected in repo_pkg or repo_pkg in norm_affected:
                    if _is_vulnerable(ver, specs):
                        matched_pkgs.append(affected_pkg)
                        current_versions[affected_pkg] = ver
                        source_files[affected_pkg] = src
                        affected_specs[affected_pkg] = specs
                    break

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
    """Return True if current_ver falls within the vulnerable range, or if unsure."""
    if not specs or current_ver in ('unknown', ''):
        return True  # Flag as potential match when no version info
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
        ss = SpecifierSet(','.join(specs))
        return Version(current_ver) in ss
    except Exception:
        return True  # Conservative: flag as potential if version parsing fails
