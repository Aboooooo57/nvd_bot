import re
from nvd_bot import config

# Known CPE vendor:product → pip/npm/go package name mappings
CPE_TO_PACKAGE: dict[str, str] = {
    'tiangolo:fastapi': 'fastapi',
    'palletsprojects:flask': 'flask',
    'palletsprojects:werkzeug': 'werkzeug',
    'djangoproject:django': 'django',
    'aiohttp:aiohttp': 'aiohttp',
    'expressjs:express': 'express',
    'nodejs:node.js': 'node',
    'python:python': 'python',
    'tornadoweb:tornado': 'tornado',
    'sqlalchemy:sqlalchemy': 'sqlalchemy',
    'psf:requests': 'requests',
    'numpy:numpy': 'numpy',
    'pillow:pillow': 'pillow',
    'urllib3:urllib3': 'urllib3',
    'cryptography:cryptography': 'cryptography',
    'pydantic:pydantic': 'pydantic',
    'starlette:starlette': 'starlette',
    'uvicorn:uvicorn': 'uvicorn',
    'springframeworkproject:spring_framework': 'spring',
    'apache:log4j': 'log4j',
}

# Generic CPE product names that are too broad to match a real dependency.
# These produce huge false-positive floods, so we ignore them unless they are
# explicitly mapped in CPE_TO_PACKAGE above.
_GENERIC_CPE_PRODUCTS: set[str] = {
    'json', 'http', 'https', 'core', 'util', 'utils', 'common', 'commons',
    'server', 'client', 'api', 'app', 'web', 'io', 'net', 'lib', 'library',
    'framework', 'module', 'modules', 'plugin', 'plugins', 'cli', 'sdk',
    'tool', 'tools', 'data', 'db', 'test', 'tests', 'demo', 'example',
    'examples', 'main', 'config', 'auth', 'admin', 'console', 'service',
}


# "<package> before 1.2.3" and friends. Anchored at the start of the window
# after a keyword, so only a version belonging to *that* package is picked up.
_VERSION_PATTERNS = [
    (r'before\s+v?(\d+\.\d+(?:\.\d+)?)', '<'),
    (r'prior\s+to\s+v?(\d+\.\d+(?:\.\d+)?)', '<'),
    (r'through\s+v?(\d+\.\d+(?:\.\d+)?)', '<='),
    (r'versions?\s*<\s*v?(\d+\.\d+(?:\.\d+)?)', '<'),
    (r'versions?\s*<=\s*v?(\d+\.\d+(?:\.\d+)?)', '<='),
]
_PROXIMITY_CHARS = 40


def is_relevant_to_watchlist(description: str) -> bool:
    """Check if description matches any watchlist keyword (fallback filter)."""
    if not description:
        return False
    watchlist = config.get('watchlist', [])
    desc_lower = description.lower()
    for keyword in watchlist:
        if re.search(r'(?i)\b' + re.escape(keyword) + r'\b', desc_lower):
            return True
    return False


def extract_affected_packages(cve_item: dict,
                              authoritative_only: bool = False) -> dict[str, list[str]]:
    """
    Returns {package_name: [specifier, ...]} e.g. {'fastapi': ['<0.109.1']}.

    Three sources, in descending order of confidence:

      1. cve.affected[]  — the CNA's own advisory. Names each package and its
         own version range, so a range can never be attached to the wrong
         package.
      2. CPE configurations — authoritative; the range travels with the
         cpeMatch entry it belongs to.
      3. Description prose — a guess, and the only source that can pair a
         package with someone else's version range.

    authoritative_only=True drops source 3. Callers that act on a match —
    opening an issue against a real repo — must use it: a guess is fine for
    "you might want to read this", never for "your dependency is vulnerable".
    """
    result: dict[str, list[str]] = {}
    cve = cve_item.get('cve', {})

    # 1. The CNA's structured advisory — best available
    _augment_from_affected(cve, result)
    trusted = set(result)

    # 2. CPE-based extraction
    for config_node in cve.get('configurations', []):
        for node in config_node.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if not cpe_match.get('vulnerable', False):
                    continue
                criteria = cpe_match.get('criteria', '')
                pkg = _package_from_cpe(criteria)
                if not pkg:
                    continue
                specs: list[str] = []
                if cpe_match.get('versionStartIncluding'):
                    specs.append(f'>={cpe_match["versionStartIncluding"]}')
                if cpe_match.get('versionEndExcluding'):
                    specs.append(f'<{cpe_match["versionEndExcluding"]}')
                if cpe_match.get('versionEndIncluding'):
                    specs.append(f'<={cpe_match["versionEndIncluding"]}')
                if pkg in trusted:
                    continue  # the CNA already gave us this package's real range
                if pkg not in result:
                    result[pkg] = specs
                else:
                    result[pkg].extend(s for s in specs if s not in result[pkg])

    # 3. Description prose — a guess; excluded when authoritative_only
    description = ''
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            description = d.get('value', '')
            break

    if not authoritative_only:
        _augment_from_description(description, result)
    return result


def _augment_from_affected(cve: dict, result: dict[str, list[str]]):
    """Read cve.affected[].affectedData[] — each entry names one package and
    carries that package's own version range."""
    for entry in cve.get('affected', []) or []:
        for data in entry.get('affectedData', []) or []:
            name = (data.get('packageName') or data.get('product') or '').strip().lower()
            if not name or name in ('n/a', '*', '-'):
                continue
            name = name.replace('_', '-')

            lowers, uppers = [], []
            for ver in data.get('versions', []) or []:
                if ver.get('status') != 'affected':
                    continue
                start = str(ver.get('version') or '').strip()
                if start and start not in ('0', '*', 'n/a', '-'):
                    lowers.append(f'>={start}')
                if ver.get('lessThan'):
                    uppers.append(f'<{ver["lessThan"]}')
                elif ver.get('lessThanOrEqual'):
                    uppers.append(f'<={ver["lessThanOrEqual"]}')

            # Specs are ANDed downstream, so several disjoint ranges would
            # collapse to something unsatisfiable. Widen to the outer bounds
            # instead: over-reporting a patched middle version is recoverable,
            # silently failing to report a vulnerable one is not.
            specs = []
            if len(lowers) == 1:
                specs += lowers
            if len(uppers) == 1:
                specs += uppers
            elif len(uppers) > 1:
                specs.append(max(uppers, key=lambda u: _ver_key(u.lstrip('<='))))

            if name not in result:
                result[name] = specs


def _ver_key(raw: str) -> tuple:
    try:
        return tuple(int(p) for p in re.findall(r'\d+', raw)[:4])
    except Exception:
        return (0,)


def _package_from_cpe(criteria: str) -> str | None:
    """Extract normalized package name from CPE 2.3 string."""
    # cpe:2.3:a:vendor:product:version:...
    parts = criteria.split(':')
    if len(parts) < 5:
        return None
    vendor = parts[3].lower()
    product = parts[4].lower()
    key = f'{vendor}:{product}'
    if key in CPE_TO_PACKAGE:
        return CPE_TO_PACKAGE[key]
    # Drop generic / too-short product names — they match unrelated packages
    if product in _GENERIC_CPE_PRODUCTS or len(product) <= 2:
        return None
    # Fallback: use product name directly, normalize underscores→hyphens
    return product.replace('_', '-')


def _augment_from_description(description: str, result: dict[str, list[str]]):
    """Last-resort guess: pair a watchlist keyword with a version range that
    appears *immediately after it* in the prose.

    The proximity requirement is the whole point. Searching the sentence at
    large let "marker before 1.10.0 ... via the FastAPI upload handler" record
    fastapi <1.10.0 — marker's ceiling pinned onto FastAPI, which then matched
    every 0.x install of it.
    """
    if not description:
        return
    watchlist = config.get('watchlist', [])

    for keyword in watchlist:
        if keyword in result:
            continue
        specs: list[str] = []
        for hit in re.finditer(r'(?i)\b' + re.escape(keyword) + r'\b', description):
            window = description[hit.end():hit.end() + _PROXIMITY_CHARS]
            for pattern, op in _VERSION_PATTERNS:
                m = re.match(pattern, window.strip(), re.IGNORECASE)
                if m:
                    specs.append(f'{op}{m.group(1)}')
            if specs:
                break
        if specs:
            result[keyword] = specs


def _augment_from_affected(cve: dict, result: dict[str, list[str]]):
    """Read cve.affected[].affectedData[] — each entry names one package and
    carries that package's own version range."""
    for entry in cve.get('affected', []) or []:
        for data in entry.get('affectedData', []) or []:
            name = (data.get('packageName') or data.get('product') or '').strip().lower()
            if not name or name in ('n/a', '*', '-'):
                continue
            name = name.replace('_', '-')

            lowers, uppers = [], []
            for ver in data.get('versions', []) or []:
                if ver.get('status') != 'affected':
                    continue
                start = str(ver.get('version') or '').strip()
                if start and start not in ('0', '*', 'n/a', '-'):
                    lowers.append(f'>={start}')
                if ver.get('lessThan'):
                    uppers.append(f'<{ver["lessThan"]}')
                elif ver.get('lessThanOrEqual'):
                    uppers.append(f'<={ver["lessThanOrEqual"]}')

            # Specs are ANDed downstream, so several disjoint ranges would
            # collapse to something unsatisfiable. Widen to the outer bounds
            # instead: over-reporting a patched middle version is recoverable,
            # silently failing to report a vulnerable one is not.
            specs = []
            if len(lowers) == 1:
                specs += lowers
            if len(uppers) == 1:
                specs += uppers
            elif len(uppers) > 1:
                specs.append(max(uppers, key=lambda u: _ver_key(u.lstrip('<='))))

            if name not in result:
                result[name] = specs


def _ver_key(raw: str) -> tuple:
    try:
        return tuple(int(p) for p in re.findall(r'\d+', raw)[:4])
    except Exception:
        return (0,)


def _package_from_cpe(criteria: str) -> str | None:
    """Extract normalized package name from CPE 2.3 string."""
    # cpe:2.3:a:vendor:product:version:...
    parts = criteria.split(':')
    if len(parts) < 5:
        return None
    vendor = parts[3].lower()
    product = parts[4].lower()
    key = f'{vendor}:{product}'
    if key in CPE_TO_PACKAGE:
        return CPE_TO_PACKAGE[key]
    # Drop generic / too-short product names — they match unrelated packages
    if product in _GENERIC_CPE_PRODUCTS or len(product) <= 2:
        return None
    # Fallback: use product name directly, normalize underscores→hyphens
    return product.replace('_', '-')

