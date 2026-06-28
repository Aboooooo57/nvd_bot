from __future__ import annotations
from abc import ABC, abstractmethod
from urllib.parse import urlparse, quote
import requests


class GitProvider(ABC):
    @abstractmethod
    def get_user_info(self, token: str) -> dict | None:
        """Return {username, display_name, repo_count} or None on failure."""

    @abstractmethod
    def list_user_repos(self, token: str, page: int = 1, per_page: int = 8) -> list[dict]:
        """Return list of {full_name, private, description, open_issues, url, _provider_type, _base_url}."""

    @abstractmethod
    def list_issues(self, owner: str, repo: str, token: str,
                    page: int = 1, per_page: int = 8) -> list[dict]:
        """Return list of {number, title, state, labels, author, url, created_at}."""

    @abstractmethod
    def get_issue(self, owner: str, repo: str, number: int, token: str) -> dict | None:
        """Return {number, title, state, labels, author, body, url, created_at} or None."""

    @property
    @abstractmethod
    def provider_type(self) -> str: ...

    @property
    @abstractmethod
    def base_url(self) -> str: ...


class GitHubProvider(GitProvider):
    def __init__(self, base_url: str = 'https://github.com'):
        self._base_url = base_url.rstrip('/')
        self._api = ('https://api.github.com'
                     if self._base_url == 'https://github.com'
                     else f'{self._base_url}/api/v3')

    @property
    def provider_type(self) -> str:
        return 'github'

    @property
    def base_url(self) -> str:
        return self._base_url

    def _headers(self, token: str) -> dict:
        return {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {token}',
        }

    def _get(self, path: str, token: str, params: dict | None = None):
        r = requests.get(f'{self._api}{path}', headers=self._headers(token),
                         params=params, timeout=20)
        remaining = r.headers.get('X-RateLimit-Remaining', '?')
        if remaining != '?' and int(remaining) < 50:
            print(f'[github] Rate limit low: {remaining} remaining')
        return r

    def get_user_info(self, token: str) -> dict | None:
        r = self._get('/user', token)
        if r.status_code == 200:
            d = r.json()
            return {
                'username': d.get('login', ''),
                'display_name': d.get('name') or d.get('login', ''),
                'repo_count': d.get('public_repos', 0),
            }
        print(f'[github] get_user_info failed: {r.status_code}')
        return None

    def list_user_repos(self, token: str, page: int = 1, per_page: int = 8) -> list[dict]:
        r = self._get('/user/repos', token,
                      params={'sort': 'updated', 'page': page, 'per_page': per_page})
        if r.status_code != 200:
            print(f'[github] list_user_repos failed: {r.status_code}')
            return []
        return [
            {
                'full_name': item['full_name'],
                'private': item.get('private', False),
                'description': item.get('description') or '',
                'open_issues': item.get('open_issues_count', 0),
                'url': item.get('html_url', ''),
                '_provider_type': 'github',
                '_base_url': self._base_url,
            }
            for item in r.json()
        ]

    def list_issues(self, owner: str, repo: str, token: str,
                    page: int = 1, per_page: int = 8) -> list[dict]:
        r = self._get(f'/repos/{owner}/{repo}/issues', token,
                      params={'state': 'open', 'page': page, 'per_page': per_page})
        if r.status_code != 200:
            print(f'[github] list_issues failed: {r.status_code}')
            return []
        return [
            {
                'number': item['number'],
                'title': item['title'],
                'state': item.get('state', 'open'),
                'labels': [lb['name'] for lb in item.get('labels', [])],
                'author': (item.get('user') or {}).get('login', ''),
                'url': item.get('html_url', ''),
                'created_at': (item.get('created_at') or '')[:10],
            }
            for item in r.json()
            if 'pull_request' not in item  # skip PRs
        ]

    def get_issue(self, owner: str, repo: str, number: int, token: str) -> dict | None:
        r = self._get(f'/repos/{owner}/{repo}/issues/{number}', token)
        if r.status_code != 200:
            return None
        item = r.json()
        return {
            'number': item['number'],
            'title': item['title'],
            'state': item.get('state', 'open'),
            'labels': [lb['name'] for lb in item.get('labels', [])],
            'author': (item.get('user') or {}).get('login', ''),
            'body': item.get('body') or '',
            'url': item.get('html_url', ''),
            'created_at': (item.get('created_at') or '')[:10],
        }


class GitLabProvider(GitProvider):
    def __init__(self, base_url: str = 'https://gitlab.com'):
        self._base_url = base_url.rstrip('/')
        self._api = f'{self._base_url}/api/v4'

    @property
    def provider_type(self) -> str:
        return 'gitlab'

    @property
    def base_url(self) -> str:
        return self._base_url

    def _headers(self, token: str) -> dict:
        return {'Authorization': f'Bearer {token}'}

    def _get(self, path: str, token: str, params: dict | None = None):
        url = path if path.startswith('http') else f'{self._api}{path}'
        return requests.get(url, headers=self._headers(token), params=params, timeout=20)

    def _project_path(self, owner: str, repo: str) -> str:
        return quote(f'{owner}/{repo}', safe='')

    def get_user_info(self, token: str) -> dict | None:
        r = self._get('/user', token)
        if r.status_code == 200:
            d = r.json()
            return {
                'username': d.get('username', ''),
                'display_name': d.get('name') or d.get('username', ''),
                'repo_count': 0,
            }
        print(f'[gitlab] get_user_info failed: {r.status_code}')
        return None

    def list_user_repos(self, token: str, page: int = 1, per_page: int = 8) -> list[dict]:
        r = self._get('/projects', token,
                      params={
                          'membership': 'true',
                          'order_by': 'last_activity_at',
                          'page': page,
                          'per_page': per_page,
                      })
        if r.status_code != 200:
            print(f'[gitlab] list_user_repos failed: {r.status_code}')
            return []
        return [
            {
                'full_name': item.get('path_with_namespace', ''),
                'private': item.get('visibility', 'private') != 'public',
                'description': item.get('description') or '',
                'open_issues': item.get('open_issues_count', 0),
                'url': item.get('web_url', ''),
                '_provider_type': 'gitlab',
                '_base_url': self._base_url,
            }
            for item in r.json()
        ]

    def list_issues(self, owner: str, repo: str, token: str,
                    page: int = 1, per_page: int = 8) -> list[dict]:
        r = self._get(f'/projects/{self._project_path(owner, repo)}/issues', token,
                      params={'state': 'opened', 'page': page, 'per_page': per_page})
        if r.status_code != 200:
            print(f'[gitlab] list_issues failed: {r.status_code}')
            return []
        return [
            {
                'number': item['iid'],
                'title': item['title'],
                'state': item.get('state', 'opened'),
                'labels': item.get('labels', []),
                'author': (item.get('author') or {}).get('username', ''),
                'url': item.get('web_url', ''),
                'created_at': (item.get('created_at') or '')[:10],
            }
            for item in r.json()
        ]

    def get_issue(self, owner: str, repo: str, number: int, token: str) -> dict | None:
        r = self._get(f'/projects/{self._project_path(owner, repo)}/issues/{number}', token)
        if r.status_code != 200:
            return None
        item = r.json()
        return {
            'number': item['iid'],
            'title': item['title'],
            'state': item.get('state', 'opened'),
            'labels': item.get('labels', []),
            'author': (item.get('author') or {}).get('username', ''),
            'body': item.get('description') or '',
            'url': item.get('web_url', ''),
            'created_at': (item.get('created_at') or '')[:10],
        }


def make_provider(provider_type: str, base_url: str) -> GitProvider:
    if provider_type == 'github':
        return GitHubProvider(base_url)
    if provider_type == 'gitlab':
        return GitLabProvider(base_url)
    raise ValueError(f'Unknown provider type: {provider_type!r}')


def detect_provider_from_url(url: str) -> tuple[str, str]:
    """Return (provider_type, base_url) inferred from a repository URL."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    scheme = parsed.scheme or 'https'
    base = f'{scheme}://{host}'
    if 'github' in host:
        return 'github', base
    return 'gitlab', base
