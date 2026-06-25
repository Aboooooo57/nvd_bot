from __future__ import annotations
import re
import json
from datetime import datetime, timezone

from nvd_bot import config
from nvd_bot.repos.profile import RepoProfile
from nvd_bot.repos.github_client import GithubClient

# Dependency file names we know how to parse
_DEP_FILES = [
    'requirements.txt',
    'requirements-dev.txt',
    'requirements/base.txt',
    'requirements/prod.txt',
    'setup.cfg',
    'pyproject.toml',
    'package.json',
    'go.mod',
    'Gemfile',
    'Pipfile',
]

# Framework detection: package name → framework label
_FRAMEWORK_MARKERS: dict[str, str] = {
    'fastapi': 'fastapi', 'flask': 'flask', 'django': 'django',
    'tornado': 'tornado', 'aiohttp': 'aiohttp', 'starlette': 'starlette',
    'express': 'express', 'next': 'next.js', 'react': 'react',
    'vue': 'vue', 'angular': 'angular', 'spring': 'spring',
    'rails': 'rails', 'sinatra': 'sinatra',
}


def scan_repo(profile: RepoProfile, gh: GithubClient) -> dict:
    """
    Fetches package files from the target repo and returns updated packages dict.
    Also writes the updated .nvd_bot/profile.json back to the target repo.
    Returns the updated packages dict.
    """
    owner, repo = _split_name(profile.name)
    if not owner:
        print(f'[scanner] Cannot parse repo name: {profile.name}')
        return profile.packages

    all_files = gh.list_files(owner, repo, token=profile.github_token)
    packages: dict[str, dict[str, str]] = {}

    for dep_file in _DEP_FILES:
        if dep_file not in all_files:
            continue
        content = gh.get_file_content(owner, repo, dep_file, token=profile.github_token)
        if not content:
            continue
        parsed = _parse_file(dep_file, content)
        if parsed:
            packages[dep_file] = parsed
            print(f'[scanner] {profile.name}: parsed {dep_file} ({len(parsed)} packages)')

    language, frameworks = _detect_language(all_files, packages)

    # Update profile fields
    profile.packages = packages
    profile.language = language
    profile.frameworks = frameworks
    profile.last_scanned_at = datetime.now(timezone.utc).isoformat()

    # Push updated profile JSON to the target repo
    _push_profile(profile, gh, owner, repo)

    return packages


def _push_profile(profile: RepoProfile, gh: GithubClient, owner: str, repo: str):
    """Commit .nvd_bot/profile.json into the tracked repo."""
    import json as _json
    profile_path = config.get('profile_file_path', '.nvd_bot/profile.json')
    # Don't include the github_token in the committed file
    safe = profile.to_dict()
    safe.pop('github_token', None)
    content = _json.dumps(safe, indent=2)
    default_branch = gh.get_default_branch(owner, repo, token=profile.github_token)
    ok = gh.commit_file(
        owner, repo, profile_path, content,
        message=f'chore: update nvd_bot profile [skip ci]',
        branch=default_branch,
        token=profile.github_token,
    )
    if ok:
        print(f'[scanner] Pushed profile to {profile.name}:{profile_path}')
    else:
        print(f'[scanner] Failed to push profile to {profile.name}')


def _parse_file(filename: str, content: str) -> dict[str, str]:
    if filename == 'requirements.txt' or filename.startswith('requirements'):
        return _parse_requirements(content)
    if filename == 'setup.cfg':
        return _parse_setup_cfg(content)
    if filename == 'pyproject.toml':
        return _parse_pyproject_toml(content)
    if filename == 'package.json':
        return _parse_package_json(content)
    if filename == 'go.mod':
        return _parse_go_mod(content)
    if filename == 'Gemfile':
        return _parse_gemfile(content)
    if filename == 'Pipfile':
        return _parse_pipfile(content)
    return {}


def _parse_requirements(content: str) -> dict[str, str]:
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        # Handle extras: package[extra]==ver → package
        m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?\s*([><=!~]+.*?)?(?:\s*#.*)?$', line)
        if m:
            pkg = m.group(1).lower().replace('_', '-')
            ver_spec = (m.group(2) or '').strip()
            # Extract pinned version from ==x.y.z
            pin = re.search(r'==\s*([\d][^\s,;]*)', ver_spec)
            result[pkg] = pin.group(1) if pin else ver_spec or 'unknown'
    return result


def _parse_setup_cfg(content: str) -> dict[str, str]:
    result = {}
    in_requires = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('install_requires'):
            in_requires = True
            continue
        if in_requires:
            if stripped.startswith('[') or (stripped and not stripped[0].isspace() and '=' in stripped):
                in_requires = False
                continue
            if stripped and not stripped.startswith('#'):
                m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?\s*([><=!~]+.*?)?$', stripped)
                if m:
                    pkg = m.group(1).lower().replace('_', '-')
                    ver_spec = (m.group(2) or '').strip()
                    pin = re.search(r'==\s*([\d][^\s,;]*)', ver_spec)
                    result[pkg] = pin.group(1) if pin else ver_spec or 'unknown'
    return result


def _parse_pyproject_toml(content: str) -> dict[str, str]:
    result = {}
    try:
        import tomllib
        data = tomllib.loads(content)
    except Exception:
        try:
            import tomli as tomllib
            data = tomllib.loads(content)
        except Exception:
            # Manual fallback: extract from [project] dependencies or [tool.poetry.dependencies]
            return _parse_pyproject_manual(content)

    # PEP 621
    deps = data.get('project', {}).get('dependencies', [])
    for dep in deps:
        m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?\s*([><=!~]+.*?)?$', dep.strip())
        if m:
            pkg = m.group(1).lower().replace('_', '-')
            ver = re.search(r'==\s*([\d][^\s,;]*)', m.group(2) or '')
            result[pkg] = ver.group(1) if ver else (m.group(2) or 'unknown').strip()

    # Poetry
    poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
    for pkg, ver in poetry_deps.items():
        if pkg.lower() == 'python':
            continue
        pkg_norm = pkg.lower().replace('_', '-')
        if isinstance(ver, str):
            clean = ver.lstrip('^~>=<!')
            result[pkg_norm] = clean or 'unknown'
        elif isinstance(ver, dict):
            v = ver.get('version', 'unknown')
            result[pkg_norm] = v.lstrip('^~>=<!') or 'unknown'

    return result


def _parse_pyproject_manual(content: str) -> dict[str, str]:
    result = {}
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r'\[project\]|\[tool\.poetry\.dependencies\]', stripped):
            in_deps = True
            continue
        if in_deps and stripped.startswith('['):
            in_deps = False
        if in_deps and '=' in stripped and not stripped.startswith('#'):
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\'^~>=<]*([\d][^\s"\']*)', stripped)
            if m:
                result[m.group(1).lower().replace('_', '-')] = m.group(2)
    return result


def _parse_package_json(content: str) -> dict[str, str]:
    result = {}
    try:
        data = json.loads(content)
    except Exception:
        return result
    for section in ('dependencies', 'devDependencies', 'peerDependencies'):
        for pkg, ver in data.get(section, {}).items():
            clean = ver.lstrip('^~>=<! ')
            result[pkg.lower()] = clean or 'unknown'
    return result


def _parse_go_mod(content: str) -> dict[str, str]:
    result = {}
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('require ('):
            in_require = True
            continue
        if in_require and stripped == ')':
            in_require = False
            continue
        if in_require or stripped.startswith('require '):
            m = re.match(r'(?:require\s+)?([^\s]+)\s+v?([\d][^\s]*)', stripped)
            if m:
                pkg = m.group(1).split('/')[-1].lower()
                result[pkg] = m.group(2)
    return result


def _parse_gemfile(content: str) -> dict[str, str]:
    result = {}
    for line in content.splitlines():
        m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
        if m:
            result[m.group(1).lower()] = m.group(2) or 'unknown'
    return result


def _parse_pipfile(content: str) -> dict[str, str]:
    result = {}
    in_packages = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ('[packages]', '[dev-packages]'):
            in_packages = True
            continue
        if in_packages and stripped.startswith('['):
            in_packages = False
        if in_packages and '=' in stripped and not stripped.startswith('#'):
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\'^~>=<]*([\d][^\s"\']*)', stripped)
            if m:
                result[m.group(1).lower().replace('_', '-')] = m.group(2)
    return result


def _detect_language(file_list: list[str], packages: dict) -> tuple[str, list[str]]:
    all_files_lower = [f.lower() for f in file_list]
    all_pkgs = set()
    for pkgs in packages.values():
        all_pkgs.update(pkgs.keys())

    language = 'unknown'
    if any(f.endswith('.py') for f in all_files_lower) or 'requirements.txt' in all_files_lower:
        language = 'python'
    elif 'package.json' in all_files_lower:
        language = 'javascript'
        if any(f.endswith('.ts') for f in all_files_lower):
            language = 'typescript'
    elif 'go.mod' in all_files_lower:
        language = 'go'
    elif 'gemfile' in all_files_lower:
        language = 'ruby'
    elif any(f.endswith('.java') for f in all_files_lower):
        language = 'java'

    frameworks = []
    for pkg_lower, label in _FRAMEWORK_MARKERS.items():
        if pkg_lower in all_pkgs:
            frameworks.append(label)

    return language, frameworks


def _split_name(name: str) -> tuple[str, str]:
    parts = name.rstrip('/').split('/')
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return '', ''
