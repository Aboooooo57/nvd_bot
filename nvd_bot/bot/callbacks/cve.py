"""Callbacks for the buttons on a CVE alert: cve:d (dismiss), cve:m (mute)."""
from __future__ import annotations
import html

from telebot.types import CallbackQuery

from nvd_bot import config
from nvd_bot.bot import state
from nvd_bot.nvd import mutes

_MAX_CALLBACK_DATA = 64  # Telegram's hard limit


def build_keyboard(cve_id: str, packages: list[str] | None = None):
    """Buttons for an alert. Returns None when there is nothing to offer."""
    from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton('🙈 Not relevant', callback_data=f'cve:d:{cve_id}'))

    # Mute the product, not the keyword that matched. Muting `node` because
    # of one Electron app would silence every genuine Node.js CVE.
    for pkg in (packages or [])[:2]:
        data = f'cve:m:{pkg}'
        if len(data.encode()) > _MAX_CALLBACK_DATA:
            continue
        kb.add(InlineKeyboardButton(f'🔇 Mute “{pkg}”', callback_data=data))
    return kb


def register():
    @state.bot.callback_query_handler(func=lambda call: call.data.startswith('cve:'))
    def handle_cve_callback(call: CallbackQuery):
        if not _authorized(call):
            state.bot.answer_callback_query(call.id, 'Unauthorized.')
            return

        parts = call.data.split(':', 2)
        action = parts[1] if len(parts) > 1 else ''
        target = parts[2] if len(parts) > 2 else ''
        mid = call.message.message_id

        if action == 'd' and target:
            # Capture the digest entry before dropping it, so undo can put
            # the whole thing back rather than just un-blocking the id.
            entry = _drop_from_digest(target)
            mutes.dismiss_cve(target, entry)
            state.bot.answer_callback_query(call.id, 'Set aside.')
            _replace(mid,
                     f'🙈 <b>Set aside</b> — <code>{html.escape(target)}</code>\n'
                     f'<i>Out of the digest and won\'t be raised again. Reversible '
                     f'any time from /dismissed.</i>',
                     keyboard=_undo_keyboard(target))

        elif action == 'r' and target:
            entry = mutes.restore_cve(target)
            if entry is None:
                state.bot.answer_callback_query(call.id, 'Not on the list.')
                return
            from nvd_bot import main
            main.restore_daily_alert(entry)
            state.bot.answer_callback_query(call.id, 'Restored.')
            back = ' It is back in the pending digest.' if entry else ''
            _replace(mid, f'↩️ <b>Restored</b> — <code>{html.escape(target)}</code>\n'
                          f'<i>It will be reported again.{back}</i>')

        elif action == 'm' and target:
            added = mutes.ignore_product(target)
            _drop_from_digest(_cve_from_message(call))
            state.bot.answer_callback_query(
                call.id, f'Muted {target}.' if added else f'{target} was already muted.')
            _replace(mid,
                     f'🔇 <b>Muted</b> — <code>{html.escape(target)}</code>\n'
                     f'<i>No more watchlist alerts for this product. CVEs affecting a '
                     f'tracked repo still come through.</i>\n\n'
                     f'Undo: <code>/unmute {html.escape(target)}</code>')
        elif action == 'u' and target.isdigit():
            products = mutes.ignored_products()
            idx = int(target)
            if idx >= len(products):
                state.bot.answer_callback_query(call.id, 'Already un-muted.')
                return
            product = products[idx]
            mutes.unignore_product(product)
            state.bot.answer_callback_query(call.id, f'Un-muted {product}.')
            _replace(mid, f'🔊 <b>Un-muted</b> — <code>{html.escape(product)}</code>')

        else:
            state.bot.answer_callback_query(call.id, 'Unknown action.')


def _cve_from_message(call) -> str:
    """Pull the CVE id out of the alert text so muting also clears that CVE
    from the pending digest."""
    import re
    text = call.message.text or call.message.caption or ''
    m = re.search(r'CVE-\d{4}-\d{4,}', text)
    return m.group(0) if m else ''


def _undo_keyboard(cve_id: str):
    from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton('↩️ Undo', callback_data=f'cve:r:{cve_id}'))
    return kb


def _drop_from_digest(cve_id: str) -> dict:
    if not cve_id:
        return {}
    from nvd_bot import main
    return main.remove_daily_alert(cve_id) or {}


def _replace(message_id: int, text: str, keyboard=None):
    """Rewrite the alert in place, so the action is visibly recorded rather
    than the message just losing its buttons."""
    try:
        state.bot.edit_message_text(text, config.CHAT_ID, message_id,
                                    parse_mode='HTML', reply_markup=keyboard)
    except Exception as e:
        print(f'[cve-cb] edit failed: {e}')


def _authorized(call) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(call)
