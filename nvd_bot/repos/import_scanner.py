from __future__ import annotations
import re
import sys

from nvd_bot.repos.profile import RepoProfile
from nvd_bot.repos.github_client import GithubClient

# Standard-library module names derived from the running interpreter
_PY_STDLIB: set[str] = set(getattr(sys, 'stdlib_module_names', set())) | {
    '__future__', 'typing_extensions', 'dataclasses', 'asyncio', 'concurrent',
}

# import-name → PyPI distribution name for common mismatches
_IMPORT_TO_PACKAGE: dict[str, str] = {
    'cv2': 'opencv-python', 'yaml': 'pyyaml', 'pil': 'pillow', 'sklearn': 'scikit-learn',
    'bs4': 'beautifulsoup4', 'dotenv': 'python-dotenv', 'jose': 'python-jose',
    'dateutil': 'python-dateutil', 'attr': 'attrs', 'google': 'google-api-python-client',
    'serial': 'pyserial', 'usb': 'pyusb', 'cryptography': 'cryptography', 'jwt': 'pyjwt',
    'redis': 'redis', 'psycopg2': 'psycopg2-binary', 'mysql': 'mysql-connector-python',
    'web3': 'web3', 'eth_account': 'eth-account', 'eth_utils': 'eth-utils',
    'telebot': 'pytelegrambotapi', 'telegram': 'python-telegram-bot', 'magic': 'python-magic',
    'OpenSSL': 'pyopenssl', 'win32api': 'pywin32', 'zmq': 'pyzmq', 'skimage': 'scikit-image',
}

_SOURCE_IMPORT_MAX_FILES = 50


def scan_source_imports(profile: RepoProfile, gh: GithubClient,
                        all_files: list[str]) -> dict[str, str]:
    """Discover third-party packages by reading import statements in source files.

    Versions can't be derived from imports, so all are returned as 'unknown'.
    Standard-library and first-party modules are filtered out.
    """
    from nvd_bot.repos.scanner import _split_name
    owner, repo = _split_name(profile.name)

    py_files = [f for f in all_files if f.endswith('.py')]
    py_files.sort(key=lambda p: (p.count('/'), len(p)))  # shallow / entrypoints first
    py_files = py_files[:_SOURCE_IMPORT_MAX_FILES]
    if not py_files:
        return {}

    # First-party names: top-level directories and .py file stems
    local: set[str] = set()
    for f in all_files:
        parts = f.split('/')
        if len(parts) > 1:
            local.add(parts[0])
        if f.endswith('.py'):
            local.add(parts[-1][:-3])

    import_re = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z0-9_]+)', re.MULTILINE)
    modules: set[str] = set()
    for f in py_files:
        content = gh.get_file_content(owner, repo, f, token=profile.github_token)
        if content:
            modules.update(m.group(1) for m in import_re.finditer(content))

    result: dict[str, str] = {}
    for mod in modules:
        if not mod or mod.startswith('_'):
            continue
        if mod in _PY_STDLIB or mod in local:
            continue
        pkg = _IMPORT_TO_PACKAGE.get(mod, mod).lower().replace('_', '-')
        result[pkg] = 'unknown'
    return result
