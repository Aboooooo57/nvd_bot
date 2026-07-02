from __future__ import annotations
import re
import json

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

# Package name → framework label, used by _detect_language
_FRAMEWORK_MARKERS: dict[str, str] = {
    'fastapi': 'fastapi', 'flask': 'flask', 'django': 'django',
    'tornado': 'tornado', 'aiohttp': 'aiohttp', 'starlette': 'starlette',
    'express': 'express', 'next': 'next.js', 'react': 'react',
    'vue': 'vue', 'angular': 'angular', 'spring': 'spring',
    'rails': 'rails', 'sinatra': 'sinatra',
}


def parse_file(filename: str, content: str) -> dict[str, str]:
    """Dispatch to the right parser based on the dependency file name."""
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


def detect_language(file_list: list[str], packages: dict) -> tuple[str, list[str]]:
    """Return (language, [framework, ...]) inferred from file extensions and package names."""
    all_files_lower = [f.lower() for f in file_list]
    all_pkgs: set[str] = set()
    for pkgs in packages.values():
        all_pkgs.update(pkgs.keys())

    language = 'unknown'
    if any(f.endswith('.py') for f in all_files_lower) or 'requirements.txt' in all_files_lower:
        language = 'python'
    elif 'package.json' in all_files_lower:
        language = 'typescript' if any(f.endswith('.ts') for f in all_files_lower) else 'javascript'
    elif 'go.mod' in all_files_lower:
        language = 'go'
    elif 'gemfile' in all_files_lower:
        language = 'ruby'
    elif any(f.endswith('.java') for f in all_files_lower):
        language = 'java'

    frameworks = [label for pkg, label in _FRAMEWORK_MARKERS.items() if pkg in all_pkgs]
    return language, frameworks


# ── Per-format parsers ────────────────────────────────────────────────────────

def _parse_requirements(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?\s*([><=!~]+.*?)?(?:\s*#.*)?$', line)
        if m:
            pkg = m.group(1).lower().replace('_', '-')
            ver_spec = (m.group(2) or '').strip()
            pin = re.search(r'==\s*([\d][^\s,;]*)', ver_spec)
            result[pkg] = pin.group(1) if pin else ver_spec or 'unknown'
    return result


def _parse_setup_py(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for m in re.finditer(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL):
        for req in re.findall(r'''['"]([^'"]+)['"]''', m.group(1)):
            result.update(_parse_requirements(req))
    return result


def _parse_setup_cfg(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
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
    result: dict[str, str] = {}
    try:
        import tomllib
        data = tomllib.loads(content)
    except Exception:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
            data = tomllib.loads(content)
        except Exception:
            return _parse_pyproject_manual(content)

    # PEP 621
    for dep in data.get('project', {}).get('dependencies', []):
        m = re.match(r'^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?\s*([><=!~]+.*?)?$', dep.strip())
        if m:
            pkg = m.group(1).lower().replace('_', '-')
            ver = re.search(r'==\s*([\d][^\s,;]*)', m.group(2) or '')
            result[pkg] = ver.group(1) if ver else (m.group(2) or 'unknown').strip()

    # Poetry
    for pkg, ver in data.get('tool', {}).get('poetry', {}).get('dependencies', {}).items():
        if pkg.lower() == 'python':
            continue
        pkg_norm = pkg.lower().replace('_', '-')
        if isinstance(ver, str):
            result[pkg_norm] = ver.lstrip('^~>=<!') or 'unknown'
        elif isinstance(ver, dict):
            result[pkg_norm] = ver.get('version', 'unknown').lstrip('^~>=<!') or 'unknown'

    return result


def _parse_pyproject_manual(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
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


def _parse_conda_yml(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    skip = {'python', 'pip', 'nodejs', 'node', 'setuptools', 'wheel', 'cython', 'conda'}
    in_deps = False
    deps_indent = None
    for raw in content.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith('#'):
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped.rstrip(':') == 'dependencies' and stripped.endswith(':'):
            in_deps = True
            deps_indent = indent
            continue
        if in_deps:
            if indent <= (deps_indent or 0) and not stripped.startswith('-'):
                break
            if not stripped.startswith('-'):
                continue
            item = stripped[1:].strip()
            if item.rstrip(':') == 'pip' and item.endswith(':'):
                continue
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*([=<>!~].*)?$', item)
            if not m:
                continue
            pkg = m.group(1).lower().replace('_', '-')
            if pkg in skip:
                continue
            ver_spec = (m.group(2) or '').strip()
            pin = re.search(r'==?\s*([\d][^\s,;]*)', ver_spec)
            result[pkg] = pin.group(1) if pin else (ver_spec.lstrip('=<>!~') or 'unknown')
    return result


def _parse_package_json(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        data = json.loads(content)
    except Exception:
        return result
    for section in ('dependencies', 'devDependencies', 'peerDependencies'):
        for pkg, ver in data.get(section, {}).items():
            result[pkg.lower()] = ver.lstrip('^~>=<! ') or 'unknown'
    return result


def _parse_go_mod(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
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
    result: dict[str, str] = {}
    for line in content.splitlines():
        m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
        if m:
            result[m.group(1).lower()] = m.group(2) or 'unknown'
    return result


def _parse_pipfile(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
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
