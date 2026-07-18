from __future__ import annotations
import base64
import requests
from nvd_bot import config


class GithubClient:
    _API = 'https://api.github.com'

    def __init__(self, default_token: str | None = None):
        self._default_token = default_token or config.GITHUB_TOKEN

    def _headers(self, token: str | None = None) -> dict:
        tok = token or self._default_token
        h = {'Accept': 'application/vnd.github.v3+json'}
        if tok:
            h['Authorization'] = f'token {tok}'
        return h

    def _get(self, path: str, token: str | None = None, params: dict | None = None):
        r = requests.get(f'{self._API}{path}', headers=self._headers(token),
                         params=params, timeout=20)
        remaining = r.headers.get('X-RateLimit-Remaining', '?')
        if remaining != '?' and int(remaining) < 50:
            print(f'[github] Rate limit low: {remaining} remaining')
        return r

    def get_latest_commit_sha(self, owner: str, repo: str,
                               token: str | None = None, branch: str | None = None) -> str | None:
        params = {'per_page': 1}
        if branch:
            params['sha'] = branch
        r = self._get(f'/repos/{owner}/{repo}/commits', token=token, params=params)
        if r.status_code == 200:
            data = r.json()
            if data:
                return data[0]['sha']
        print(f'[github] get_latest_commit_sha failed: {r.status_code}')
        return None

    def get_default_branch(self, owner: str, repo: str, token: str | None = None) -> str:
        r = self._get(f'/repos/{owner}/{repo}', token=token)
        if r.status_code == 200:
            return r.json().get('default_branch', 'main')
        return 'main'

    def list_files(self, owner: str, repo: str, token: str | None = None) -> list[str]:
        r = self._get(f'/repos/{owner}/{repo}/git/trees/HEAD',
                      token=token, params={'recursive': '1'})
        if r.status_code == 200:
            data = r.json()
            if data.get('truncated'):
                print(f'[github] {owner}/{repo}: tree truncated — some paths may be missing')
            return [item['path'] for item in data.get('tree', [])
                    if item.get('type') == 'blob']
        print(f'[github] list_files failed: {r.status_code}')
        return []

    def get_file_content(self, owner: str, repo: str, path: str,
                          token: str | None = None) -> str | None:
        r = self._get(f'/repos/{owner}/{repo}/contents/{path}', token=token)
        if r.status_code == 200:
            data = r.json()
            if data.get('encoding') == 'base64':
                return base64.b64decode(data['content']).decode('utf-8', errors='replace')
        if r.status_code != 404:
            print(f'[github] get_file_content {path} failed: {r.status_code}')
        return None

    def get_file_sha(self, owner: str, repo: str, path: str,
                      token: str | None = None) -> str | None:
        r = self._get(f'/repos/{owner}/{repo}/contents/{path}', token=token)
        if r.status_code == 200:
            return r.json().get('sha')
        return None

    def create_branch(self, owner: str, repo: str, branch_name: str,
                       base_sha: str, token: str | None = None) -> bool:
        r = requests.post(
            f'{self._API}/repos/{owner}/{repo}/git/refs',
            headers=self._headers(token),
            json={'ref': f'refs/heads/{branch_name}', 'sha': base_sha},
            timeout=20,
        )
        return r.status_code in (200, 201, 422)  # 422 = already exists

    def commit_file(self, owner: str, repo: str, path: str, content: str,
                     message: str, branch: str, token: str | None = None) -> str | None:
        """Create or update a file. Returns the new commit's sha on success, None on failure."""
        existing_sha = self.get_file_sha(owner, repo, path, token)
        payload: dict = {
            'message': message,
            'content': base64.b64encode(content.encode()).decode(),
            'branch': branch,
        }
        if existing_sha:
            payload['sha'] = existing_sha

        r = requests.put(
            f'{self._API}/repos/{owner}/{repo}/contents/{path}',
            headers=self._headers(token),
            json=payload,
            timeout=20,
        )
        if r.status_code in (200, 201):
            return r.json().get('commit', {}).get('sha')
        print(f'[github] commit_file failed: {r.status_code} {r.text[:200]}')
        return None

    def create_pull_request(self, owner: str, repo: str, title: str, body: str,
                             head: str, base: str, token: str | None = None) -> str | None:
        r = requests.post(
            f'{self._API}/repos/{owner}/{repo}/pulls',
            headers=self._headers(token),
            json={'title': title, 'body': body, 'head': head, 'base': base},
            timeout=20,
        )
        if r.status_code in (200, 201):
            return r.json().get('html_url')
        print(f'[github] create_pr failed: {r.status_code} {r.text[:200]}')
        return None

    def create_issue(self, owner: str, repo: str, title: str, body: str,
                     labels: list[str] | None = None, token: str | None = None) -> str | None:
        payload: dict = {'title': title, 'body': body}
        if labels:
            payload['labels'] = labels
        r = requests.post(
            f'{self._API}/repos/{owner}/{repo}/issues',
            headers=self._headers(token),
            json=payload,
            timeout=20,
        )
        if r.status_code in (200, 201):
            return r.json().get('html_url')
        print(f'[github] create_issue failed: {r.status_code} {r.text[:200]}')
        return None
