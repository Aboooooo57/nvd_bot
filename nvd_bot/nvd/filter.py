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


def extract_affected_packages(cve_item: dict) -> dict[str, list[str]]:
    """
    Returns {package_name: [specifier, ...]} e.g. {'fastapi': ['<0.109.1', '>=0.1.0']}.
    Combines CPE data (authoritative) with description regex (fallback).
    """
    result: dict[str, list[str]] = {}
    cve = cve_item.get('cve', {})

    # 1. CPE-based extraction
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
                if pkg not in result:
                    result[pkg] = specs
                else:
                    result[pkg].extend(s for s in specs if s not in result[pkg])

    # 2. Description regex fallback (adds packages not caught by CPE)
    description = ''
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            description = d.get('value', '')
            break

    _augment_from_description(description, result)
    return result


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
    """Extract version ranges from free-text description patterns."""
    if not description:
        return
    # Patterns: "before 1.2.3", "prior to 1.2.3", "through 1.2.3", "versions < 1.2.3"
    patterns = [
        (r'before\s+v?([\d]+\.[\d]+(?:\.[\d]+)?)', '<'),
        (r'prior\s+to\s+v?([\d]+\.[\d]+(?:\.[\d]+)?)', '<'),
        (r'through\s+v?([\d]+\.[\d]+(?:\.[\d]+)?)', '<='),
        (r'versions?\s*<\s*v?([\d]+\.[\d]+(?:\.[\d]+)?)', '<'),
        (r'versions?\s*<=\s*v?([\d]+\.[\d]+(?:\.[\d]+)?)', '<='),
    ]
    watchlist = config.get('watchlist', [])
    desc_lower = description.lower()

    for keyword in watchlist:
        if not re.search(r'(?i)\b' + re.escape(keyword) + r'\b', desc_lower):
            continue
        if keyword in result:
            continue
        specs: list[str] = []
        for pattern, op in patterns:
            m = re.search(pattern, description, re.IGNORECASE)
            if m:
                specs.append(f'{op}{m.group(1)}')
        if keyword not in result:
            result[keyword] = specs
