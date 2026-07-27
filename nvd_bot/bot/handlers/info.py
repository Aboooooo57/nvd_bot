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
        from nvd_bot.nvd import poll_state, enrichment, mutes
        from nvd_bot.repos.issue_ledger import IssueLedger

        repos = state._registry.list_repos()
        last_poll = poll_state.get_last_poll()
        last_str = last_poll.strftime('%Y-%m-%d %H:%M UTC') if last_poll else 'never'
        kev_age = enrichment.kev_cache_age_hours()
        kev_str = 'never fetched' if kev_age == float('inf') else f'{kev_age:.1f}h ago'

        quiet = not config.get('per_cve_alerts', False)
        mode = ('digest only' if quiet else 'every CVE')
        immediate = config.get('immediate_severity') or 'none'

        # With per-CVE alerts off, silence is the normal state — these numbers
        # are the only way to tell a quiet day from a broken bot.
        from nvd_bot.version import version_string
        send(
            f'🤖 <b>NVD Bot Status</b>  <code>{html.escape(version_string())}</code>\n\n'
            f'📦 Tracked repos: {len(repos)}\n'
            f'🔔 Alert mode: <b>{mode}</b> (immediate at {html.escape(str(immediate))}'
            f'{", KEV" if config.get("immediate_on_kev", True) else ""})\n'
            f'📊 Queued for next summary: {len(_pending_summary())}\n'
            f'⏳ Awaiting CVSS score: {poll_state.pending_count()}\n'
            f'🔒 Issues on record: {IssueLedger().count()}\n'
            f'🔇 Muted products: {len(mutes.ignored_products())}\n\n'
            f'🕐 Last successful CVE poll: {last_str}\n'
            f'⚡ KEV cache: {kev_str}\n'
            f'🔍 Watchlist: {", ".join(config.get("watchlist", []))}\n'
            f'🤖 LLM: {config.get("llm_provider")} / {config.get("llm_model")}\n'
            f'⏱ CVE poll: every {config.get("nvd_poll_interval_minutes")} min\n'
            f'⏱ Commit poll: every {config.get("commit_poll_interval_minutes")} min\n'
            f'📅 Summary at {config.get("daily_summary_time")}'
        )

    @state.bot.message_handler(commands=['mutes'])
    def cmd_mutes(msg: Message):
        if not _authorized(msg): return
        from nvd_bot.nvd import mutes
        products = mutes.ignored_products()
        dismissed = mutes.dismissed_count()

        if not products:
            send(f'🔇 <b>No muted products.</b>\n\n'
                 f'Dismissed CVEs: {dismissed}\n\n'
                 f'<i>Use the buttons on an alert to mute a product you don\'t care about.</i>')
            return

        kb = InlineKeyboardMarkup()
        for i, p in enumerate(products):
            kb.add(InlineKeyboardButton(f'🔊 Un-mute {p}', callback_data=f'cve:u:{i}'))
        send(
            f'🔇 <b>Muted products</b> ({len(products)})\n\n'
            + '\n'.join(f'• <code>{html.escape(p)}</code>' for p in products)
            + f'\n\nDismissed CVEs: {dismissed}\n'
            + '<i>Muting only suppresses watchlist noise — CVEs affecting a tracked '
              'repo always come through.</i>',
            reply_markup=kb)

    @state.bot.message_handler(commands=['unmute'])
    def cmd_unmute(msg: Message):
        if not _authorized(msg): return
        from nvd_bot.nvd import mutes
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            send('Usage: /unmute &lt;product&gt;\nOr use the buttons in /mutes')
            return
        product = parts[1].strip().lower()
        if mutes.unignore_product(product):
            send(f'🔊 Un-muted: <code>{html.escape(product)}</code>')
        else:
            send(f'❌ Not muted: <code>{html.escape(product)}</code>')

    @state.bot.message_handler(commands=['version'])
    def cmd_version(msg: Message):
        if not _authorized(msg): return
        from nvd_bot import version as ver
        rows = '\n'.join(f'{label}: <code>{html.escape(value)}</code>'
                         for label, value in ver.build_details())
        send(f'🏷 <b>NVD Bot</b>\n\n{rows}')

    @state.bot.message_handler(commands=['summary'])
    def cmd_summary(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        peek = len(parts) > 1 and parts[1].strip().lower() == 'peek'

        job = state._summary_job
        if job is None:
            send('⏳ Still starting up — try again in a moment.')
            return
        if not job(drain=not peek):
            send('📭 Nothing recorded since the last summary.')
        elif peek:
            send('👆 Preview only — these stay queued for the scheduled summary.')

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
        from nvd_bot.version import version_string
        send(
            f'<b>NVD Bot Commands</b>  <code>{html.escape(version_string())}</code>\n\n'
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
            '/version — Show the running version and commit\n'
            '/mutes — List muted products and dismissed CVEs\n'
            '/unmute &lt;product&gt; — Un-mute a product\n'
            '/summary — Send the CVE digest now (clears the queue)\n'
            '/summary peek — Preview it without clearing\n'
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


def _pending_summary() -> list:
    """Alerts waiting for the next digest. Read from disk so /status works
    even before anything has been recorded this process."""
    from nvd_bot import main
    return main._load_daily_alerts()


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
