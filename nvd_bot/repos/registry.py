from __future__ import annotations
import json
import os
import hashlib
import threading
from nvd_bot import config
from nvd_bot.repos.profile import RepoProfile


class RepoRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        os.makedirs(config.REPOS_DIR, exist_ok=True)
        self._ensure_registry()

    def _ensure_registry(self):
        if not os.path.exists(config.REPO_REGISTRY_FILE):
            with open(config.REPO_REGISTRY_FILE, 'w') as f:
                json.dump({'repos': []}, f, indent=2)

    def _load_registry(self) -> list[str]:
        try:
            with open(config.REPO_REGISTRY_FILE, 'r') as f:
                return json.load(f).get('repos', [])
        except Exception:
            return []

    def _save_registry(self, ids: list[str]):
        with open(config.REPO_REGISTRY_FILE, 'w') as f:
            json.dump({'repos': ids}, f, indent=2)

    def _profile_path(self, repo_id: str) -> str:
        return os.path.join(config.REPOS_DIR, f'{repo_id}.json')

    def _generate_id(self, url: str) -> str:
        slug = url.rstrip('/').split('/')[-2:]
        slug_str = '-'.join(slug).lower().replace('_', '-')
        short_hash = hashlib.sha1(url.encode()).hexdigest()[:6]
        return f'{slug_str}-{short_hash}'

    def add_repo(self, url: str, github_token: str | None = None) -> RepoProfile:
        with self._lock:
            repo_id = self._generate_id(url)
            ids = self._load_registry()

            # If already tracked, return existing
            if repo_id in ids:
                return self._load_profile(repo_id)

            # Parse owner/repo from URL
            parts = url.rstrip('/').split('/')
            name = '/'.join(parts[-2:]) if len(parts) >= 2 else url

            profile = RepoProfile(
                id=repo_id,
                url=url,
                name=name,
                github_token=github_token,
            )
            self._save_profile(profile)
            ids.append(repo_id)
            self._save_registry(ids)
            return profile

    def remove_repo(self, repo_id: str) -> bool:
        with self._lock:
            ids = self._load_registry()
            if repo_id not in ids:
                return False
            ids.remove(repo_id)
            self._save_registry(ids)
            path = self._profile_path(repo_id)
            if os.path.exists(path):
                os.remove(path)
            return True

    def get_repo(self, repo_id: str) -> RepoProfile | None:
        with self._lock:
            ids = self._load_registry()
            if repo_id not in ids:
                return None
            return self._load_profile(repo_id)

    def list_repos(self) -> list[RepoProfile]:
        with self._lock:
            ids = self._load_registry()
            profiles = []
            for repo_id in ids:
                p = self._load_profile(repo_id)
                if p:
                    profiles.append(p)
            return profiles

    def update_profile(self, profile: RepoProfile):
        with self._lock:
            self._save_profile(profile)

    def _save_profile(self, profile: RepoProfile):
        path = self._profile_path(profile.id)
        with open(path, 'w') as f:
            json.dump(profile.to_dict(), f, indent=2)

    def _load_profile(self, repo_id: str) -> RepoProfile | None:
        path = self._profile_path(repo_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r') as f:
                return RepoProfile.from_dict(json.load(f))
        except Exception as e:
            print(f'[registry] Failed to load {repo_id}: {e}')
            return None

    def find_by_name(self, name: str) -> RepoProfile | None:
        """Find repo by 'owner/repo' name."""
        for p in self.list_repos():
            if p.name.lower() == name.lower():
                return p
        return None
