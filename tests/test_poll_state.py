"""Poll watermark and pending-CVE store.

The watermark is the part that loses data silently when wrong, so most of
these tests are about what happens when a fetch fails.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def setup_module():
    os.chdir(tempfile.mkdtemp())
    from nvd_bot import config
    config.load()


def _fresh():
    """Clear state between tests."""
    from nvd_bot import config
    if os.path.exists(config.POLL_STATE_FILE):
        os.remove(config.POLL_STATE_FILE)


# ── watermark ─────────────────────────────────────────────────────────────────

def test_first_run_uses_lookback():
    from nvd_bot.nvd import poll_state
    _fresh()
    now = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
    start, skipped = poll_state.compute_window(now)
    assert start == now - timedelta(minutes=6)
    assert skipped is None


def test_window_resumes_from_watermark():
    from nvd_bot.nvd import poll_state
    _fresh()
    now = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
    last = now - timedelta(minutes=42)
    poll_state.set_last_poll(last)
    start, skipped = poll_state.compute_window(now)
    assert start == last, 'must resume exactly where the last poll ended'
    assert skipped is None


def test_long_downtime_is_clamped_and_reported():
    from nvd_bot.nvd import poll_state
    _fresh()
    now = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
    poll_state.set_last_poll(now - timedelta(days=5))
    start, skipped = poll_state.compute_window(now)
    assert start == now - timedelta(hours=24), 'clamped to max_catchup_hours'
    assert skipped is not None, 'gap must be surfaced, not swallowed'


def test_failed_fetch_does_not_advance_watermark():
    """The regression that matters: a failed poll must re-cover its window."""
    from nvd_bot.nvd import poll_state, client
    _fresh()
    before = datetime(2026, 7, 26, 11, 0, tzinfo=timezone.utc)
    poll_state.set_last_poll(before)

    client._request = lambda params: None  # simulate timeout / API error
    assert client.get_new_cves() == []
    assert poll_state.get_last_poll() == before, 'watermark moved despite failure'


def test_successful_empty_fetch_does_advance_watermark():
    """Empty is not the same as failed — no CVEs published is real progress."""
    from nvd_bot.nvd import poll_state, client
    _fresh()
    before = datetime(2026, 7, 26, 11, 0, tzinfo=timezone.utc)
    poll_state.set_last_poll(before)

    client._request = lambda params: []
    assert client.get_new_cves() == []
    assert poll_state.get_last_poll() > before


# ── pending store ─────────────────────────────────────────────────────────────

def test_pending_add_list_drop():
    from nvd_bot.nvd import poll_state
    _fresh()
    poll_state.add_pending('CVE-2026-1')
    poll_state.add_pending('CVE-2026-2')
    assert poll_state.list_pending() == ['CVE-2026-1', 'CVE-2026-2']
    poll_state.drop_pending('CVE-2026-1')
    assert poll_state.list_pending() == ['CVE-2026-2']


def test_pending_add_is_idempotent():
    from nvd_bot.nvd import poll_state
    _fresh()
    poll_state.add_pending('CVE-2026-1')
    first = poll_state._read_unlocked()['pending']['CVE-2026-1']
    poll_state.add_pending('CVE-2026-1')
    assert poll_state._read_unlocked()['pending']['CVE-2026-1'] == first, \
        're-adding must not reset the age, or it never expires'
    assert poll_state.pending_count() == 1


def test_pending_prune_drops_only_aged_entries():
    from nvd_bot.nvd import poll_state
    _fresh()
    now = datetime.now(timezone.utc)
    poll_state.add_pending('CVE-old', first_seen=now - timedelta(days=20))
    poll_state.add_pending('CVE-new', first_seen=now - timedelta(days=2))
    dropped = poll_state.prune_pending(14)
    assert dropped == ['CVE-old']
    assert poll_state.list_pending() == ['CVE-new']


def test_corrupt_state_file_does_not_crash():
    from nvd_bot import config
    from nvd_bot.nvd import poll_state
    _fresh()
    with open(config.POLL_STATE_FILE, 'w') as f:
        f.write('{ this is not json')
    assert poll_state.get_last_poll() is None
    assert poll_state.list_pending() == []
    poll_state.add_pending('CVE-2026-9')  # recovers by overwriting
    assert poll_state.list_pending() == ['CVE-2026-9']
