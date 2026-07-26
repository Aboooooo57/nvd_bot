"""Single source of truth for the bot's version.

__version__ is the human-facing number and is bumped by hand. GIT_SHA is
injected at image build time (see the Dockerfile's ARG) and is what actually
identifies a running build — a hand-maintained constant can be stale if
someone forgets to bump it, a sha cannot.
"""
from __future__ import annotations
import os

__version__ = '2.0.0'

_UNSET = ('', 'unknown', 'none')


def _env(name: str) -> str:
    val = os.getenv(name, '').strip()
    return '' if val.lower() in _UNSET else val


GIT_SHA = _env('GIT_SHA')
BUILD_DATE = _env('BUILD_DATE')


def version_string() -> str:
    """Short form for status lines, e.g. 'v2.0.0 (b637b40)'."""
    if GIT_SHA:
        return f'v{__version__} ({GIT_SHA})'
    return f'v{__version__}'


def build_details() -> list[tuple[str, str]]:
    """Label/value pairs for /version. Only includes what's actually known."""
    rows = [('Version', f'v{__version__}')]
    if GIT_SHA:
        rows.append(('Commit', GIT_SHA))
    else:
        rows.append(('Commit', 'not baked in — running from a checkout?'))
    if BUILD_DATE:
        rows.append(('Built', BUILD_DATE))
    return rows
