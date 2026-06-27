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
    'requirements.in',
    'requirements/base.txt',
    'requirements/prod.txt',
    'setup.cfg',
    'setup.py',
    'pyproject.toml',
    'environment.yml',
    'environment-linux.yml',
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


def scan_repo(profile: RepoProfile, gh: GithubClient, llm=None) -> dict:
    """
    Fetches package files from the target repo and returns updated packages dict.
    Also writes the updated .nvd_bot/profile.json back to the target repo.
    Falls back to LLM-based package inference if no standard dep files are found.
    Returns the updated packages dict.
    """
    owner, repo = _split_name(profile.name)
    if not owner:
        print(f'[scanner] Cannot parse repo name: {profile.name}')
        return profile.packages

    all_files = gh.list_files(owner, repo, token=profile.github_token)
    packages: dict[str, dict[str, str]] = {}

    for dep_file in _DEP_FILES:
        # Match by suffix so files in any subdirectory are found
        matched_paths = [f for f in all_files if f == dep_file or f.endswith('/' + dep_file)]
        for matched_path in matched_paths:
            content = gh.get_file_content(owner, repo, matched_path, token=profile.github_token)
            if not content:
                continue
            parsed = _parse_file(dep_file, content)
            if parsed:
                packages[matched_path] = parsed
                print(f'[scanner] {profile.name}: parsed {matched_path} ({len(parsed)} packages)')

    # LLM fallback: if no dep files found, ask the LLM to infer packages from file list
    profile._llm_scan_error = None  # transient; not serialised by to_dict()
    if not packages and llm:
        print(f'[scanner] {profile.name}: no dep files found, trying LLM inference…')
        try:
            packages = _infer_packages_with_llm(profile, gh, all_files, llm)
        except Exception as e:
            profile._llm_scan_error = str(e)
            print(f'[scanner] {profile.name}: LLM inference failed: {e}')

    language, frameworks = _detect_language(all_files, packages)

    # Update profile fields
    profile.packages = packages
    profile.language = language
    profile.frameworks = frameworks
    profile.last_scanned_at = datetime.now(timezone.utc).isoformat()

    # Push updated profile JSON to the target repo
    _push_profile(profile, gh, owner, repo)

    return packages


_AGENT_MAX_STEPS = 6
_AGENT_FILE_CAP = 4000   # max chars of a fetched file fed back to the model
_AGENT_LIST_CAP = 150    # max file paths shown to the model

_AGENT_SYSTEM_PROMPT = (
    'You are a dependency-analyzer agent inspecting a source repository to determine the '
    'external packages/libraries it depends on. You may request the contents of files to '
    'investigate (dependency manifests, setup files, imports, docs).\n\n'
    'Respond with EXACTLY ONE JSON object per turn, no extra text, in one of these forms:\n'
    '  {"action": "read_file", "path": "<repo-relative path>"}\n'
    '  {"action": "final", "packages": {"package-name": "version-or-unknown", ...}}\n\n'
    'Inspect likely files (e.g. requirements*.txt, setup.py, pyproject.toml, '
    'environment.yml, package.json, or a few source files for imports) before finalizing. '
    'In the final answer include only real external dependencies — not standard-library '
    'modules and not the project itself. Use "unknown" when you cannot determine a version.'
)


def _infer_packages_with_llm(profile: RepoProfile, gh: GithubClient,
                              all_files: list[str], llm) -> dict:
    """Agentic inference: the LLM requests files in a loop until it reports dependencies."""
    import re as _re
    owner, repo = _split_name(profile.name)
    file_set = set(all_files)

    file_list = '\n'.join(all_files[:_AGENT_LIST_CAP])
    if len(all_files) > _AGENT_LIST_CAP:
        file_list += f'\n… ({len(all_files) - _AGENT_LIST_CAP} more files not shown)'

    messages = [
        {'role': 'system', 'content': _AGENT_SYSTEM_PROMPT},
        {'role': 'user', 'content': (
            f'Repository: {profile.name}\n\n'
            f'Files in repo:\n{file_list}\n\n'
            'Determine the external dependencies. Request files as needed, then finalize.'
        )},
    ]

    read_paths: set[str] = set()
    for step in range(_AGENT_MAX_STEPS):
        # Errors propagate so scan_repo can surface the reason.
        response = llm.chat(messages, max_tokens=1000)
        json_match = _re.search(r'\{.*\}', response, _re.DOTALL)
        if not json_match:
            print(f'[scanner] {profile.name}: agent step {step}: no JSON in reply, stopping')
            break

        try:
            action = json.loads(json_match.group())
        except Exception:
            print(f'[scanner] {profile.name}: agent step {step}: bad JSON, stopping')
            break

        if action.get('action') == 'final':
            pkgs = {k: str(v) for k, v in (action.get('packages') or {}).items() if k}
            if pkgs:
                print(f'[scanner] {profile.name}: agent inferred {len(pkgs)} packages '
                      f'in {step + 1} step(s)')
                return {'llm-inferred': pkgs}
            return {}

        if action.get('action') == 'read_file':
            path = (action.get('path') or '').strip()
            messages.append({'role': 'assistant', 'content': json_match.group()})
            if path in read_paths:
                feedback = f'(already provided {path}; please request a different file or finalize)'
            elif path not in file_set:
                feedback = f'(file not found: {path}; choose a path from the list or finalize)'
            else:
                read_paths.add(path)
                content = gh.get_file_content(owner, repo, path, token=profile.github_token)
                if not content:
                    feedback = f'(file is empty or unreadable: {path})'
                else:
                    feedback = f'Contents of {path}:\n{content[:_AGENT_FILE_CAP]}'
            messages.append({'role': 'user', 'content': feedback})
            continue

        # Unrecognized action
        print(f'[scanner] {profile.name}: agent step {step}: unknown action, stopping')
        break

    print(f'[scanner] {profile.name}: agent did not finalize within {_AGENT_MAX_STEPS} steps')
    return {}


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
    if filename == 'setup.py':
        return _parse_setup_py(content)
    if filename == 'pyproject.toml':
        return _parse_pyproject_toml(content)
    if 'environment' in filename and filename.endswith(('.yml', '.yaml')):
        return _parse_conda_yml(content)
    if filename == 'package.json':
        return _parse_package_json(content)
    if filename == 'go.mod':
        return _parse_go_mod(content)
    if filename == 'Gemfile':
        return _parse_gemfile(content)
    if filename == 'Pipfile':
        return _parse_pipfile(content)
    return {}


def _parse_setup_py(content: str) -> dict[str, str]:
    """Extract install_requires entries from setup.py."""
    result: dict[str, str] = {}
    for m in re.finditer(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL):
        # Each requirement is a quoted string, e.g. "aiohttp==3.8.1", 'web3>=6'
        for req in re.findall(r'''['"]([^'"]+)['"]''', m.group(1)):
            result.update(_parse_requirements(req))
    return result


def _parse_conda_yml(content: str) -> dict[str, str]:
    """Parse a conda environment.yml dependencies list, including a nested pip: block."""
    result: dict[str, str] = {}
    skip = {'python', 'pip', 'nodejs', 'node', 'setuptools', 'wheel', 'cython', 'conda'}
    in_deps = False
    in_pip = False
    deps_indent = None
    for raw in content.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith('#'):
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if stripped.rstrip(':') == 'dependencies' and stripped.endswith(':'):
            in_deps = True
            in_pip = False
            deps_indent = indent
            continue
        if in_deps:
            # A new top-level key at or below the dependencies indent ends the block
            if indent <= (deps_indent or 0) and not stripped.startswith('-'):
                break
            if not stripped.startswith('-'):
                continue
            item = stripped[1:].strip()
            if item.rstrip(':') == 'pip' and item.endswith(':'):
                in_pip = True
                continue
            # pip sub-items are more deeply indented "- pkg==ver"
            name_spec = item
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*([=<>!~].*)?$', name_spec)
            if not m:
                in_pip = in_pip and indent > (deps_indent or 0) + 2
                continue
            pkg = m.group(1).lower().replace('_', '-')
            if pkg in skip:
                continue
            ver_spec = (m.group(2) or '').strip()
            pin = re.search(r'==?\s*([\d][^\s,;]*)', ver_spec)
            result[pkg] = pin.group(1) if pin else (ver_spec.lstrip('=<>!~') or 'unknown')
    return result


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
