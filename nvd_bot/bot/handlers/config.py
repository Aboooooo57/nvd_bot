"""Handlers for config commands: /settings, /setconfig, /addkeyword, /removekeyword."""
from __future__ import annotations
import html

from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Message

from nvd_bot import config as cfg
from nvd_bot.bot import state
from nvd_bot.bot.utils import send, coerce


def register():
    @state.bot.message_handler(commands=['settings'])
    def cmd_settings(msg: Message):
        if not _authorized(msg): return
        settings = cfg.all_settings()
        lines = ['<b>Current Settings</b> (data/config.json)\n']
        for k, v in sorted(settings.items()):
            lines.append(f'<code>{k}</code>: {html.escape(str(v))}')
        send('\n'.join(lines))

    @state.bot.message_handler(commands=['setconfig'])
    def cmd_setconfig(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=2)
        if len(parts) < 3:
            send('Usage: /setconfig &lt;key&gt; &lt;value&gt;\nExample: /setconfig severity_threshold HIGH')
            return
        key, raw_val = parts[1], parts[2]
        val = coerce(raw_val)
        ok = cfg.set(key, val)
        if ok:
            send(f'✅ <code>{html.escape(key)}</code> = <code>{html.escape(str(val))}</code>')
        else:
            send('❌ Failed to save config.')

    @state.bot.message_handler(commands=['addkeyword'])
    def cmd_addkeyword(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            send('Usage: /addkeyword &lt;word&gt;')
            return
        word = parts[1].strip().lower()
        ok = cfg.add_watchlist_keyword(word)
        if ok:
            send(f'✅ Added keyword: <code>{html.escape(word)}</code>')
        else:
            send(f'ℹ️ Keyword already in list: <code>{html.escape(word)}</code>')

    @state.bot.message_handler(commands=['removekeyword'])
    def cmd_removekeyword(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            kws = cfg.get('watchlist', [])
            if not kws:
                send('Watchlist Is Empty.')
                return
            kb = InlineKeyboardMarkup()
            for i, kw in enumerate(kws):
                kb.add(InlineKeyboardButton(f'❌ {kw}', callback_data=f'adm:rmkw:{i}'))
            send('<b>Select Keyword to Remove:</b>', reply_markup=kb)
            return
        word = parts[1].strip().lower()
        ok = cfg.remove_watchlist_keyword(word)
        if ok:
            send(f'✅ Keyword Removed: <code>{html.escape(word)}</code>')
        else:
            send(f'❌ Keyword Not Found: <code>{html.escape(word)}</code>')


def _authorized(msg) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(msg)
