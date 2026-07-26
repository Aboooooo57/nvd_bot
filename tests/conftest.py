"""Shared test setup.

Enrichment is stubbed for every test by default, so no test can reach the
network and none can be affected by a stub another test file left behind.
Tests that care about KEV/EPSS override it themselves.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _EmptyResp:
    status_code = 200

    def __init__(self, url):
        self._url = url

    def json(self):
        if 'cisa.gov' in self._url:
            return {'vulnerabilities': []}
        return {'data': []}


@pytest.fixture(autouse=True)
def _no_network():
    from nvd_bot.nvd import enrichment
    original = enrichment.requests.get
    enrichment.requests.get = lambda url, params=None, timeout=None: _EmptyResp(url)
    yield
    enrichment.requests.get = original
