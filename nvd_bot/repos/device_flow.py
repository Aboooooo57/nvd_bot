from __future__ import annotations
import requests

SCOPES = 'repo read:user'


def start(client_id: str, base_url: str = 'https://github.com') -> dict:
    """Start GitHub Device Authorization Flow. Returns {device_code, user_code, verification_uri, expires_in, interval}."""
    r = requests.post(
        f'{base_url.rstrip("/")}/login/device/code',
        headers={'Accept': 'application/json'},
        data={'client_id': client_id, 'scope': SCOPES},
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()
    if 'error' in data:
        raise RuntimeError(f'Device flow start error: {data["error"]} — {data.get("error_description", "")}')
    return data


def poll_token(client_id: str, client_secret: str, device_code: str,
               base_url: str = 'https://github.com') -> str | None:
    """Single poll attempt. Returns access_token if granted, None if still pending. Raises on denied/expired."""
    r = requests.post(
        f'{base_url.rstrip("/")}/login/oauth/access_token',
        headers={'Accept': 'application/json'},
        data={
            'client_id': client_id,
            'client_secret': client_secret,
            'device_code': device_code,
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        },
        timeout=20,
    )
    if r.status_code != 200:
        return None
    data = r.json()
    error = data.get('error')
    if error in ('authorization_pending', 'slow_down'):
        return None
    if error in ('access_denied', 'expired_token'):
        raise RuntimeError(error)
    if error:
        raise RuntimeError(f'Device flow error: {error}')
    return data.get('access_token') or None
