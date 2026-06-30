"""Shared utility functions used across bot handler modules."""
from __future__ import annotations
import html

from nvd_bot.bot import state

_GIT_ICONS = {'github': '🐙', 'gitlab': '🦊'}


def send(text: str, reply_markup=None, chat_id: str | None = None):
    """Send a Telegram HTML message to the configured chat."""
    from nvd_bot import config
    cid = chat_id or config.CHAT_ID
    try:
        state.bot.send_message(cid, text, parse_mode='HTML', reply_markup=reply_markup)
    except Exception as e:
        print(f'[bot] send error: {e}')


def edit_or_send(text: str, reply_markup, edit_msg_id,
                 disable_web_page_preview: bool = False):
    """Edit an existing message in place, or send a new one if no message id given."""
    from nvd_bot import config
    if edit_msg_id:
        try:
            state.bot.edit_message_text(
                text, config.CHAT_ID, edit_msg_id,
                parse_mode='HTML', reply_markup=reply_markup,
                disable_web_page_preview=disable_web_page_preview,
            )
            return
        except Exception:
            pass
    send(text, reply_markup=reply_markup)


def pkg_summary(profile) -> str:
    """Human-readable package count string for scan messages."""
    count = profile.package_count()
    if count == 0:
        err = getattr(profile, '_llm_scan_error', None)
        if err:
            return f'no dep files found, and LLM inference failed: {err[:200]}'
        return 'no dependency files found (LLM inference found nothing either)'
    if 'llm-inferred' in profile.packages:
        return f'{count} packages found (LLM-inferred — verify manually)'
    if 'import-scan' in profile.packages:
        return f'{count} packages found (from source imports — versions unknown, verify manually)'
    return f'{count} packages found'


def coerce(val: str):
    """Convert a string config value to the appropriate Python type."""
    if val.lower() == 'true':
        return True
    if val.lower() == 'false':
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val
