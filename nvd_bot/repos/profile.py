from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class RepoProfile:
    id: str
    url: str
    name: str                         # "owner/repo"
    language: str = 'unknown'
    frameworks: list = field(default_factory=list)
    packages: dict = field(default_factory=dict)  # {"requirements.txt": {"pkg": "ver"}}
    last_commit_sha: Optional[str] = None
    last_scanned_at: Optional[str] = None
    active_fixes: list = field(default_factory=list)
    enabled: bool = True
    auto_pr: bool = False
    github_token: Optional[str] = None
    # Per-repo config overrides (any key from config.json)
    overrides: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'url': self.url,
            'name': self.name,
            'language': self.language,
            'frameworks': self.frameworks,
            'packages': self.packages,
            'last_commit_sha': self.last_commit_sha,
            'last_scanned_at': self.last_scanned_at,
            'active_fixes': self.active_fixes,
            'enabled': self.enabled,
            'auto_pr': self.auto_pr,
            'github_token': self.github_token,
            'overrides': self.overrides,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RepoProfile:
        return cls(
            id=data['id'],
            url=data['url'],
            name=data['name'],
            language=data.get('language', 'unknown'),
            frameworks=data.get('frameworks', []),
            packages=data.get('packages', {}),
            last_commit_sha=data.get('last_commit_sha'),
            last_scanned_at=data.get('last_scanned_at'),
            active_fixes=data.get('active_fixes', []),
            enabled=data.get('enabled', True),
            auto_pr=data.get('auto_pr', False),
            github_token=data.get('github_token'),
            overrides=data.get('overrides', {}),
        )

    def get_config(self, key: str, global_value):
        """Return per-repo override if set, else the global config value."""
        return self.overrides.get(key, global_value)

    def set_override(self, key: str, value):
        self.overrides[key] = value

    def package_count(self) -> int:
        return sum(len(pkgs) for pkgs in self.packages.values())

    def all_packages_flat(self) -> dict[str, tuple[str, str]]:
        """Returns {normalized_name: (version, source_file)} for all packages."""
        result = {}
        for source_file, pkgs in self.packages.items():
            for pkg, ver in pkgs.items():
                result[_normalize(pkg)] = (ver, source_file)
        return result


def _normalize(name: str) -> str:
    return name.lower().replace('_', '-').split('[')[0].strip()
