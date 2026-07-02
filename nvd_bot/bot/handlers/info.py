"""Handlers for info commands: /status, /llmcheck, /help, /adduser, /removeuser."""
from __future__ import annotations
import html
import time

from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Message

from nvd_bot import config
from nvd_bot.bot import state
from nvd_bot.bot.utils import send


def register():
    @state.bot.message_handler(commands=['status'])
    def cmd_status(msg: Message):
        if not _authorized(msg): return
        repos = state._registry.list_repos()
        send(
            f'🤖 <b>NVD Bot Status</b>\n\n'
            f'📦 Tracked repos: {len(repos)}\n'
            f'🔍 Watchlist: {", ".join(config.get("watchlist", []))}\n'
            f'🤖 LLM: {config.get("llm_provider")} / {config.get("llm_model")}\n'
            f'⏱ CVE poll: every {config.get("nvd_poll_interval_minutes")} min\n'
            f'⏱ Commit poll: every {config.get("commit_poll_interval_minutes")} min'
        )

    @state.bot.message_handler(commands=['llmcheck'])
    def cmd_llmcheck(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        model_override = parts[1].strip() if len(parts) > 1 else None
        model = model_override or config.get('llm_model', 'unknown')
        send(f'🔍 Testing LLM: <code>{html.escape(model)}</code>…')
        state._executor.submit(_llmcheck_task, model, model_override is not None)

    @state.bot.message_handler(commands=['adduser'])
    def cmd_adduser(msg: Message):
        if not _is_owner(msg): return
        parts = msg.text.split()
        if len(parts) < 2 or not parts[1].isdigit():
            send('Usage: /adduser &lt;telegram-user-id&gt;')
            return
        uid = int(parts[1])
        ok = config.add_allowed_user(uid)
        if ok:
            send(f'✅ User <code>{uid}</code> added to allowlist.')
        else:
            send(f'ℹ️ User <code>{uid}</code> is already in the allowlist.')

    @state.bot.message_handler(commands=['removeuser'])
    def cmd_removeuser(msg: Message):
        if not _is_owner(msg): return
        parts = msg.text.split()
        if len(parts) < 2 or not parts[1].isdigit():
            users = config.get('allowed_user_ids', [])
            if not users:
                send('No Additional Users In Allowlist.')
                return
            kb = InlineKeyboardMarkup()
            for u in users:
                kb.add(InlineKeyboardButton(f'❌ User {u}', callback_data=f'adm:rmu:{u}'))
            send('<b>Select User to Remove:</b>', reply_markup=kb)
            return
        uid = int(parts[1])
        ok = config.remove_allowed_user(uid)
        if ok:
            send(f'✅ User <code>{uid}</code> Removed From Allowlist.')
        else:
            send(f'❌ User <code>{uid}</code> Not Found In Allowlist.')

    @state.bot.message_handler(commands=['help', 'start'])
    def cmd_help(msg: Message):
        if not _authorized(msg): return
        send(
            '<b>NVD Bot Commands</b>\n\n'
            '<b>Repo Management</b>\n'
            '/addrepo &lt;url&gt; [token] — Track a GitHub repo\n'
            '/removerepo &lt;id&gt; — Stop tracking a repo\n'
            '/listrepos — List all tracked repos\n'
            '/scanrepo &lt;id&gt; — Force re-scan a repo now\n'
            '/repoprofile &lt;id&gt; — Show full repo profile JSON\n'
            '/setrepo &lt;id&gt; &lt;key&gt; &lt;value&gt; — Set per-repo setting\n\n'
            '<b>Configuration</b>\n'
            '/settings — Show all settings\n'
            '/setconfig &lt;key&gt; &lt;value&gt; — Update a setting live\n'
            '/addkeyword &lt;word&gt; — Add CVE watchlist keyword\n'
            '/removekeyword &lt;word&gt; — Remove watchlist keyword\n\n'
            '<b>Info</b>\n'
            '/status — System status overview\n'
            '/llmcheck [model] — Test LLM connection\n\n'
            '<b>User Management (owner only)</b>\n'
            '/adduser &lt;id&gt; — Allow a Telegram user to use this bot\n'
            '/removeuser &lt;id&gt; — Remove a user from the allowlist\n\n'
            '<b>Git Account Management</b>\n'
            '/connectgit &lt;github|gitlab&gt; [url] — Connect a git account\n'
            '/disconnectgit &lt;index&gt; — Remove a connected account\n'
            '/gitaccounts — List your connected accounts\n'
            '/myrepos — Browse and track repos from your accounts\n'
            '/issues &lt;repo-id&gt; — View issues for a tracked repo'
        )


def _llmcheck_task(model: str, is_override: bool):
    provider = state._llm.active_provider()
    cfg_provider = config.get('llm_provider', 'openrouter')
    auto_note = ' (auto-detected)' if provider != cfg_provider else ''
    base_url = config.LITELLM_BASE_URL or '—'
    key_status = 'set' if (
        (provider == 'openrouter' and config.OPENROUTER_API_KEY) or
        (provider == 'litellm_proxy' and config.LITELLM_API_KEY)
    ) else 'NOT SET'

    model_warn = ''
    if provider == 'litellm_proxy' and model.startswith('openrouter/') and not is_override:
        model_warn = '\n⚠️ Model has <code>openrouter/</code> prefix — use /setconfig llm_model &lt;model&gt; to fix'

    try:
        t0 = time.monotonic()
        response = state._llm.generate(
            system_prompt='',
            user_prompt='Reply with just the word OK',
            max_tokens=200,
            model_override=model if is_override else None,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        snippet = (response or '').strip()[:100]
        send(
            f'✅ <b>LLM healthy</b>\n'
            f'Provider: <code>{html.escape(provider)}{auto_note}</code>\n'
            f'Model: <code>{html.escape(model)}</code>\n'
            f'Base URL: <code>{html.escape(base_url)}</code>\n'
            f'API key: {key_status}\n'
            f'Latency: {elapsed_ms} ms\n'
            f'Response: <i>{html.escape(snippet)}</i>'
            + model_warn
        )
    except Exception as e:
        send(
            f'❌ <b>LLM check failed</b>\n'
            f'Provider: <code>{html.escape(provider)}{auto_note}</code>\n'
            f'Model: <code>{html.escape(model)}</code>\n'
            f'Base URL: <code>{html.escape(base_url)}</code>\n'
            f'API key: {key_status}\n'
            f'Error: {html.escape(str(e))}'
            + model_warn
        )


def _authorized(msg) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(msg)


def _is_owner(msg) -> bool:
    from nvd_bot.bot.core import is_owner
    return is_owner(msg)
