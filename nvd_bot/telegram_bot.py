from __future__ import annotations
import html
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery, Message, BotCommand

from nvd_bot import config

if TYPE_CHECKING:
    from nvd_bot.repos.registry import RepoRegistry
    from nvd_bot.fixes.pending import PendingFixStore
    from nvd_bot.repos.github_client import GithubClient
    from nvd_bot.fixes.llm_client import LLMClient
    from nvd_bot.repos.git_account_store import GitAccountStore
    from nvd_bot.repos.git_providers import GitProvider

bot: telebot.TeleBot = None  # initialized in init()
_executor = ThreadPoolExecutor(max_workers=4)

# Shared references injected by main.py
_registry: RepoRegistry = None
_pending: PendingFixStore = None
_gh: GithubClient = None
_llm: LLMClient = None
_git_store: GitAccountStore = None

# Per-user git browsing state (in-memory, non-persistent)
_awaiting_token: dict[int, dict] = {}   # uid → {provider_type, base_url}
_awaiting_url: dict[int, dict] = {}     # uid → {provider_type} — waiting for self-hosted URL
_user_repo_cache: dict[int, dict] = {}  # uid → {acc_idx, gh_page, repos, has_more}
_user_issue_ctx: dict[int, dict] = {}   # uid → {provider, owner, repo, token, issues, gh_page, has_more}


def init(registry, pending, gh, llm, git_store=None):
    global bot, _registry, _pending, _gh, _llm, _git_store
    _registry = registry
    _pending = pending
    _gh = gh
    _llm = llm
    _git_store = git_store
    bot = telebot.TeleBot(config.TELEGRAM_BOT_TOKEN, parse_mode='HTML')
    _register_handlers()
    try:
        bot.set_my_commands([
            BotCommand('addrepo',        'Track a repo by URL'),
            BotCommand('removerepo',     'Stop tracking a repo'),
            BotCommand('listrepos',      'List all tracked repos'),
            BotCommand('scanrepo',       'Force re-scan a repo now'),
            BotCommand('repoprofile',    'Show full repo profile JSON'),
            BotCommand('setrepo',        'Set a per-repo config override'),
            BotCommand('connectgit',     'Connect a GitHub or GitLab account'),
            BotCommand('disconnectgit',  'Disconnect a git account'),
            BotCommand('gitaccounts',    'List your connected git accounts'),
            BotCommand('myrepos',        'Browse repos from your git accounts'),
            BotCommand('issues',         'View issues for a tracked repo'),
            BotCommand('pending',        'List pending fix proposals'),
            BotCommand('settings',       'Show all current settings'),
            BotCommand('setconfig',      'Update a config value live'),
            BotCommand('addkeyword',     'Add a CVE watchlist keyword'),
            BotCommand('removekeyword',  'Remove a watchlist keyword'),
            BotCommand('llmcheck',       'Test LLM connection'),
            BotCommand('status',         'System status overview'),
            BotCommand('help',           'Show all commands'),
            BotCommand('adduser',        'Allow a user (owner only)'),
            BotCommand('removeuser',     'Remove a user (owner only)'),
        ])
        print('[bot] Commands registered with Telegram.')
    except Exception as e:
        print(f'[bot] Failed to register commands: {e}')
    return bot


# ── Authorization ────────────────────────────────────────────────────────────

def _authorized(msg) -> bool:
    uid = msg.from_user.id if msg.from_user else None
    if not uid:
        return False
    if config.TELEGRAM_OWNER_ID and uid == config.TELEGRAM_OWNER_ID:
        return True
    return uid in config.get('allowed_user_ids', [])


def _is_owner(msg) -> bool:
    uid = msg.from_user.id if msg.from_user else None
    return bool(uid and config.TELEGRAM_OWNER_ID and uid == config.TELEGRAM_OWNER_ID)


# ── Helpers ───────────────────────────────────────────────────────────────────

def send(text: str, reply_markup=None, chat_id: str | None = None):
    cid = chat_id or config.CHAT_ID
    try:
        bot.send_message(cid, text, parse_mode='HTML', reply_markup=reply_markup)
    except Exception as e:
        print(f'[bot] send error: {e}')


def _fix_keyboard(fix_id: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton('✅ Accept', callback_data=f'fix:accept:{fix_id}'),
        InlineKeyboardButton('❌ Deny',   callback_data=f'fix:deny:{fix_id}'),
    )
    kb.row(InlineKeyboardButton('📋 Details', callback_data=f'fix:details:{fix_id}'))
    return kb


def send_fix_proposal(fix):
    icon = '🚨' if fix.severity in ('HIGH', 'CRITICAL') else '⚠️'
    text = (
        f'🔧 <b>Fix Proposal</b> for <b>{html.escape(fix.repo_name)}</b>\n\n'
        f'{icon} CVE: <b>{html.escape(fix.cve_id)}</b>  |  Severity: <b>{fix.severity}</b>\n'
        f'📄 File: <code>{html.escape(fix.file_path)}</code>\n'
        f'🔑 Type: {fix.fix_type}\n\n'
        f'<i>{html.escape(fix.explanation[:300])}</i>\n\n'
        f'Accept to create a GitHub PR with this fix.'
    )
    try:
        msg = bot.send_message(
            config.CHAT_ID, text,
            parse_mode='HTML',
            reply_markup=_fix_keyboard(fix.fix_id),
        )
        _pending.update_status(fix.fix_id, 'pending', telegram_message_id=msg.message_id)
    except Exception as e:
        print(f'[bot] send_fix_proposal error: {e}')


# ── Handler registration ──────────────────────────────────────────────────────

def _register_handlers():

    # ── /addrepo ─────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['addrepo'])
    def cmd_addrepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=2)
        if len(parts) < 2:
            send('Usage: /addrepo &lt;github-url&gt; [optional-token]')
            return
        url = parts[1].strip()
        token = parts[2].strip() if len(parts) > 2 else None
        send(f'Adding repo <code>{html.escape(url)}</code>…')
        _executor.submit(_add_repo_task, url, token)

    def _add_repo_task(url: str, token: str | None):
        from nvd_bot.repos.scanner import scan_repo
        try:
            profile = _registry.add_repo(url, github_token=token)
            send(f'✅ Repo added: <b>{html.escape(profile.name)}</b>\nID: <code>{profile.id}</code>\nScanning packages…')
            scan_repo(profile, _gh, _llm)
            _registry.update_profile(profile)
            send(f'📦 Scan complete for <b>{html.escape(profile.name)}</b>: '
                 f'{_pkg_summary(profile)}, language: {profile.language}')
        except Exception as e:
            send(f'❌ Error adding repo: {html.escape(str(e))}')

    # ── /removerepo ───────────────────────────────────────────────────────────
    @bot.message_handler(commands=['removerepo'])
    def cmd_removerepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split()
        if len(parts) < 2:
            repos = _registry.list_repos()
            if not repos:
                send('No Repos Tracked Yet. Use /addrepo to add one.')
                return
            kb = InlineKeyboardMarkup()
            for i, p in enumerate(repos):
                kb.add(InlineKeyboardButton(f'🗑 {p.name}', callback_data=f'adm:rm:{i}'))
            send('<b>Select Repo to Remove:</b>', reply_markup=kb)
            return
        repo_id = parts[1].strip()
        ok = _registry.remove_repo(repo_id)
        if ok:
            send(f'✅ Repo <code>{repo_id}</code> Removed.')
        else:
            send(f'❌ Repo ID <code>{repo_id}</code> Not Found.')

    # ── /listrepos ────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['listrepos'])
    def cmd_listrepos(msg: Message):
        if not _authorized(msg): return
        repos = _registry.list_repos()
        if not repos:
            send('No repos tracked yet. Use /addrepo &lt;url&gt; to add one.')
            return
        lines = ['<b>Tracked Repositories</b>\n']
        for p in repos:
            status = '✅' if p.enabled else '⏸'
            auto = '⚡ auto-PR' if p.auto_pr else ''
            lines.append(
                f'{status} <b>{html.escape(p.name)}</b> {auto}\n'
                f'   ID: <code>{p.id}</code>\n'
                f'   Lang: {p.language} | Pkgs: {p.package_count()} | '
                f'Last scan: {(p.last_scanned_at or "never")[:10]}'
            )
        send('\n\n'.join(lines))

    # ── /scanrepo ─────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['scanrepo'])
    def cmd_scanrepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split()
        if len(parts) < 2:
            repos = _registry.list_repos()
            if not repos:
                send('No Repos Tracked Yet. Use /addrepo to add one.')
                return
            kb = InlineKeyboardMarkup()
            for i, p in enumerate(repos):
                kb.add(InlineKeyboardButton(f'🔄 {p.name}', callback_data=f'adm:sc:{i}'))
            send('<b>Select Repo to Scan:</b>', reply_markup=kb)
            return
        repo_id = parts[1].strip()
        profile = _registry.get_repo(repo_id)
        if not profile:
            send(f'❌ Repo <code>{repo_id}</code> Not Found.')
            return
        send(f'🔄 Scanning <b>{html.escape(profile.name)}</b>…')
        _executor.submit(_scan_task, profile)

    def _scan_task(profile):
        from nvd_bot.repos.scanner import scan_repo
        try:
            scan_repo(profile, _gh, _llm)
            _registry.update_profile(profile)
            send(f'✅ Scan done: <b>{html.escape(profile.name)}</b> — '
                 f'{_pkg_summary(profile)}, language: {profile.language}')
        except Exception as e:
            send(f'❌ Scan failed: {html.escape(str(e))}')

    # ── /repoprofile ──────────────────────────────────────────────────────────
    @bot.message_handler(commands=['repoprofile'])
    def cmd_repoprofile(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split()
        if len(parts) < 2:
            send('Usage: /repoprofile &lt;repo-id&gt;')
            return
        profile = _registry.get_repo(parts[1].strip())
        if not profile:
            send('❌ Repo not found.')
            return
        safe = profile.to_dict()
        safe.pop('github_token', None)
        text = f'<b>{html.escape(profile.name)}</b>\n\n<pre>{html.escape(json.dumps(safe, indent=2))}</pre>'
        send(text)

    # ── /pending ──────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['pending'])
    def cmd_pending(msg: Message):
        if not _authorized(msg): return
        fixes = _pending.list_pending()
        if not fixes:
            send('No pending fix proposals.')
            return
        for fix in fixes[:10]:  # cap at 10 to avoid flooding
            icon = '🚨' if fix.severity in ('HIGH', 'CRITICAL') else '⚠️'
            text = (
                f'{icon} <b>{html.escape(fix.cve_id)}</b> — <b>{html.escape(fix.repo_name)}</b>\n'
                f'File: <code>{html.escape(fix.file_path)}</code> | {fix.fix_type}'
            )
            bot.send_message(config.CHAT_ID, text, parse_mode='HTML',
                             reply_markup=_fix_keyboard(fix.fix_id))

    # ── /settings ─────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['settings'])
    def cmd_settings(msg: Message):
        if not _authorized(msg): return
        cfg = config.all_settings()
        lines = ['<b>Current Settings</b> (data/config.json)\n']
        for k, v in sorted(cfg.items()):
            lines.append(f'<code>{k}</code>: {html.escape(str(v))}')
        send('\n'.join(lines))

    # ── /setconfig ────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['setconfig'])
    def cmd_setconfig(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=2)
        if len(parts) < 3:
            send('Usage: /setconfig &lt;key&gt; &lt;value&gt;\nExample: /setconfig severity_threshold HIGH')
            return
        key, raw_val = parts[1], parts[2]
        # Type coercion
        val = _coerce(raw_val)
        ok = config.set(key, val)
        if ok:
            send(f'✅ <code>{html.escape(key)}</code> = <code>{html.escape(str(val))}</code>')
        else:
            send('❌ Failed to save config.')

    # ── /addkeyword / /removekeyword ──────────────────────────────────────────
    @bot.message_handler(commands=['addkeyword'])
    def cmd_addkeyword(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            send('Usage: /addkeyword &lt;word&gt;')
            return
        word = parts[1].strip().lower()
        ok = config.add_watchlist_keyword(word)
        if ok:
            send(f'✅ Added keyword: <code>{html.escape(word)}</code>')
        else:
            send(f'ℹ️ Keyword already in list: <code>{html.escape(word)}</code>')

    @bot.message_handler(commands=['removekeyword'])
    def cmd_removekeyword(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            kws = config.get('watchlist', [])
            if not kws:
                send('Watchlist Is Empty.')
                return
            kb = InlineKeyboardMarkup()
            for i, kw in enumerate(kws):
                kb.add(InlineKeyboardButton(f'❌ {kw}', callback_data=f'adm:rmkw:{i}'))
            send('<b>Select Keyword to Remove:</b>', reply_markup=kb)
            return
        word = parts[1].strip().lower()
        ok = config.remove_watchlist_keyword(word)
        if ok:
            send(f'✅ Keyword Removed: <code>{html.escape(word)}</code>')
        else:
            send(f'❌ Keyword Not Found: <code>{html.escape(word)}</code>')

    # ── /setrepo ──────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['setrepo'])
    def cmd_setrepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=3)
        if len(parts) < 4:
            send('Usage: /setrepo &lt;repo-id&gt; &lt;key&gt; &lt;value&gt;\n'
                 'Example: /setrepo abc123 auto_pr true')
            return
        repo_id, key, raw_val = parts[1], parts[2], parts[3]
        profile = _registry.get_repo(repo_id)
        if not profile:
            send(f'❌ Repo <code>{repo_id}</code> not found.')
            return
        val = _coerce(raw_val)
        # Handle top-level fields directly
        if hasattr(profile, key) and key not in ('id', 'name', 'url'):
            setattr(profile, key, val)
        else:
            profile.set_override(key, val)
        _registry.update_profile(profile)
        send(f'✅ <b>{html.escape(profile.name)}</b>: <code>{key}</code> = <code>{html.escape(str(val))}</code>')

    # ── /llmcheck ─────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['llmcheck'])
    def cmd_llmcheck(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=1)
        model_override = parts[1].strip() if len(parts) > 1 else None
        model = model_override or config.get('llm_model', 'unknown')
        send(f'🔍 Testing LLM: <code>{html.escape(model)}</code>…')
        _executor.submit(_llmcheck_task, model, model_override is not None)

    def _llmcheck_task(model: str, is_override: bool):
        import time
        provider = _llm.active_provider()
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
            response = _llm.generate(
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

    # ── /status ───────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['status'])
    def cmd_status(msg: Message):
        if not _authorized(msg): return
        repos = _registry.list_repos()
        pending_count = len(_pending.list_pending())
        send(
            f'🤖 <b>NVD Bot Status</b>\n\n'
            f'📦 Tracked repos: {len(repos)}\n'
            f'⏳ Pending fixes: {pending_count}\n'
            f'🔍 Watchlist: {", ".join(config.get("watchlist", []))}\n'
            f'🤖 LLM: {config.get("llm_provider")} / {config.get("llm_model")}\n'
            f'⏱ CVE poll: every {config.get("nvd_poll_interval_minutes")} min\n'
            f'⏱ Commit poll: every {config.get("commit_poll_interval_minutes")} min'
        )

    # ── /adduser / /removeuser (owner-only) ──────────────────────────────────
    @bot.message_handler(commands=['adduser'])
    def cmd_adduser(msg: Message):
        if not _is_owner(msg):
            return
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

    @bot.message_handler(commands=['removeuser'])
    def cmd_removeuser(msg: Message):
        if not _is_owner(msg):
            return
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

    # ── /help ─────────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['help', 'start'])
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
            '<b>Fix Management</b>\n'
            '/pending — List pending fix proposals\n\n'
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

    # ── PAT paste handler (must be registered before the catch-all) ──────────
    @bot.message_handler(
        func=lambda m: (m.from_user and m.from_user.id in _awaiting_token
                        and m.text and not m.text.startswith('/'))
    )
    def handle_token_paste(msg: Message):
        if not _authorized(msg):
            return
        uid = msg.from_user.id
        ctx = _awaiting_token.pop(uid, None)
        if not ctx:
            return
        try:
            bot.delete_message(msg.chat.id, msg.message_id)
        except Exception:
            pass
        token = msg.text.strip()
        from nvd_bot.repos.git_providers import make_provider
        provider = make_provider(ctx['provider_type'], ctx['base_url'])
        try:
            info = provider.get_user_info(token)
        except Exception as e:
            _awaiting_token[uid] = ctx
            send(f'❌ Token validation failed: {html.escape(str(e))}\nPlease try again.')
            return
        if not info:
            _awaiting_token[uid] = ctx
            send('❌ Invalid token or insufficient permissions. Please check and try again.')
            return
        username = info.get('username', 'unknown')
        _git_store.add_account(uid, ctx['provider_type'], ctx['base_url'], token, username)
        send(
            f'✅ Connected as <b>{html.escape(username)}</b> on '
            f'{html.escape(ctx["base_url"])}!\n\nUse /myrepos to browse your repositories.'
        )

    # ── Self-hosted URL paste handler ─────────────────────────────────────────
    @bot.message_handler(
        func=lambda m: (m.from_user and m.from_user.id in _awaiting_url
                        and m.text and not m.text.startswith('/'))
    )
    def handle_url_paste(msg: Message):
        if not _authorized(msg):
            return
        uid = msg.from_user.id
        ctx = _awaiting_url.pop(uid, None)
        if not ctx:
            return
        raw = msg.text.strip()
        if not raw.startswith('http'):
            _awaiting_url[uid] = ctx
            send('❌ Please enter a valid URL starting with <code>https://</code>')
            return
        _start_connect_flow(uid, ctx['provider_type'], raw.rstrip('/'))

    # ── /connectgit ───────────────────────────────────────────────────────────
    @bot.message_handler(commands=['connectgit'])
    def cmd_connectgit(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=2)
        uid = msg.from_user.id
        if len(parts) < 2:
            # Show provider picker keyboard
            kb = InlineKeyboardMarkup()
            kb.row(
                InlineKeyboardButton('🐙 GitHub', callback_data='gh:cg:gh'),
                InlineKeyboardButton('🦊 GitLab', callback_data='gh:cg:gl'),
            )
            kb.row(
                InlineKeyboardButton('⚙️ GitHub Enterprise', callback_data='gh:cg:ghe'),
                InlineKeyboardButton('⚙️ GitLab Self-hosted', callback_data='gh:cg:gls'),
            )
            bot.send_message(config.CHAT_ID, '<b>Connect a Git account</b>\n\nChoose a provider:',
                             reply_markup=kb, parse_mode='HTML')
            return
        provider_type = parts[1].strip().lower()
        if provider_type not in ('github', 'gitlab'):
            send('❌ Type must be <code>github</code> or <code>gitlab</code>.')
            return
        base_url = (parts[2].strip() if len(parts) > 2
                    else ('https://github.com' if provider_type == 'github' else 'https://gitlab.com'))
        _start_connect_flow(uid, provider_type, base_url.rstrip('/'))

    # ── /disconnectgit ────────────────────────────────────────────────────────
    @bot.message_handler(commands=['disconnectgit'])
    def cmd_disconnectgit(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        parts = msg.text.split()
        if len(parts) < 2 or not parts[1].isdigit():
            _show_gitaccounts(uid)
            return
        idx = int(parts[1])
        ok = _git_store.remove_account(uid, idx)
        if ok:
            send(f'✅ Account #{idx} Disconnected.')
        else:
            send(f'❌ Account #{idx} Not Found.')

    # ── /gitaccounts ──────────────────────────────────────────────────────────
    @bot.message_handler(commands=['gitaccounts'])
    def cmd_gitaccounts(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        _show_gitaccounts(uid)

    def _show_gitaccounts(uid: int):
        accounts = _git_store.list_accounts(uid)
        if not accounts:
            kb = InlineKeyboardMarkup()
            kb.add(InlineKeyboardButton('➕ Connect Account', callback_data='gh:cg:pick'))
            send('No Git Accounts Connected.', reply_markup=kb)
            return
        lines = ['<b>Connected Git Accounts</b>\n']
        for acc in accounts:
            icon = _GIT_ICONS.get(acc['type'], '🔗')
            host = acc['base_url']
            host_str = '' if host in ('https://github.com', 'https://gitlab.com') else f' ({html.escape(host)})'
            lines.append(f'{icon} <b>{html.escape(acc["username"])}</b> — {acc["type"].title()}{host_str}')
        kb = InlineKeyboardMarkup()
        for acc in accounts:
            icon = _GIT_ICONS.get(acc['type'], '🔗')
            label = f'❌ Disconnect {icon} {acc["username"]}'
            kb.add(InlineKeyboardButton(label, callback_data=f'gh:rmac:{acc["idx"]}'))
        send('\n'.join(lines), reply_markup=kb)

    # ── /myrepos ──────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['myrepos'])
    def cmd_myrepos(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        accounts = _git_store.list_accounts(uid)
        if not accounts:
            send('No git accounts connected. Use /connectgit &lt;github|gitlab&gt; to add one.')
            return
        if len(accounts) == 1:
            send(f'🔄 Fetching repos for <b>{html.escape(accounts[0]["username"])}</b>…')
            _executor.submit(_fetch_and_show_repos, uid, 0, 1, None)
            return
        kb = InlineKeyboardMarkup()
        for acc in accounts:
            icon = _GIT_ICONS.get(acc['type'], '🔗')
            label = f'{icon} {acc["username"]} ({acc["type"]})'
            kb.add(InlineKeyboardButton(label, callback_data=f'gh:acc:{acc["idx"]}'))
        send('<b>Select a git account:</b>', reply_markup=kb)

    # ── /issues ───────────────────────────────────────────────────────────────
    @bot.message_handler(commands=['issues'])
    def cmd_issues(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            repos = _registry.list_repos()
            if not repos:
                send('No Repos Tracked Yet. Use /addrepo to add one.')
                return
            kb = InlineKeyboardMarkup()
            for i, p in enumerate(repos):
                kb.add(InlineKeyboardButton(f'🐛 {p.name}', callback_data=f'adm:iss:{i}'))
            send('<b>Select Repo to View Issues:</b>', reply_markup=kb)
            return
        profile = _registry.get_repo(parts[1].strip())
        if not profile:
            send(f'❌ Repo <code>{html.escape(parts[1].strip())}</code> not found.')
            return
        from nvd_bot.repos.git_providers import make_provider, detect_provider_from_url
        provider_type, base_url = detect_provider_from_url(profile.url)
        acc = _git_store.find_account_for_host(uid, provider_type, base_url)
        token = (acc['token'] if acc else profile.github_token or config.GITHUB_TOKEN)
        if not token:
            send('❌ No token for this repo. Connect your account with /connectgit first.')
            return
        owner, repo_name = (profile.name.split('/', 1) if '/' in profile.name
                            else ('', profile.name))
        provider = make_provider(provider_type, base_url)
        send(f'🔄 Fetching issues for <b>{html.escape(profile.name)}</b>…')
        _executor.submit(_fetch_and_show_issues, uid, provider, owner, repo_name, token, 1, None)

    # ── gh:* callback handler ─────────────────────────────────────────────────
    @bot.callback_query_handler(func=lambda call: call.data.startswith('gh:'))
    def handle_gh_callback(call: CallbackQuery):
        if not _authorized(call):
            bot.answer_callback_query(call.id, 'Unauthorized.')
            return
        bot.answer_callback_query(call.id)
        uid = call.from_user.id
        parts = call.data.split(':')
        action = parts[1] if len(parts) > 1 else ''
        mid = call.message.message_id

        if action == 'nop':
            return

        elif action == 'cg':
            choice = parts[2] if len(parts) > 2 else ''
            if choice == 'pick':
                kb = InlineKeyboardMarkup()
                kb.row(
                    InlineKeyboardButton('🐙 GitHub', callback_data='gh:cg:gh'),
                    InlineKeyboardButton('🦊 GitLab', callback_data='gh:cg:gl'),
                )
                kb.row(
                    InlineKeyboardButton('⚙️ GitHub Enterprise', callback_data='gh:cg:ghe'),
                    InlineKeyboardButton('⚙️ GitLab Self-hosted', callback_data='gh:cg:gls'),
                )
                bot.edit_message_text('<b>Connect a Git Account</b>\n\nChoose a Provider:',
                                      config.CHAT_ID, mid, reply_markup=kb, parse_mode='HTML')
            elif choice == 'gh':
                bot.edit_message_text('<b>Connect GitHub</b>\n\n🔄 Starting…',
                                      config.CHAT_ID, mid, parse_mode='HTML')
                _executor.submit(_start_connect_flow, uid, 'github', 'https://github.com')
            elif choice == 'gl':
                bot.edit_message_text('<b>Connect GitLab</b>\n\n🔄 Starting…',
                                      config.CHAT_ID, mid, parse_mode='HTML')
                _executor.submit(_start_connect_flow, uid, 'gitlab', 'https://gitlab.com')
            elif choice in ('ghe', 'gls'):
                provider_type = 'github' if choice == 'ghe' else 'gitlab'
                example = ('https://github.mycompany.com' if choice == 'ghe'
                           else 'https://gitlab.mycompany.com')
                _awaiting_url[uid] = {'provider_type': provider_type}
                bot.edit_message_text(
                    f'Enter Your Self-Hosted URL:\n<code>{html.escape(example)}</code>',
                    config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'rmac':
            idx = int(parts[2])
            ok = _git_store.remove_account(uid, idx)
            if ok:
                bot.edit_message_text('✅ Account Disconnected.', config.CHAT_ID, mid, parse_mode='HTML')
            else:
                bot.edit_message_text('❌ Account Not Found.', config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'acc':
            acc_idx = int(parts[2])
            acc = _git_store.get_account(uid, acc_idx)
            if acc:
                bot.edit_message_text(
                    f'🔄 Fetching repos for <b>{html.escape(acc["username"])}</b>…',
                    config.CHAT_ID, mid, parse_mode='HTML')
            _executor.submit(_fetch_and_show_repos, uid, acc_idx, 1, mid)

        elif action == 'rp':
            acc_idx, gh_page = int(parts[2]), int(parts[3])
            _executor.submit(_fetch_and_show_repos, uid, acc_idx, gh_page, mid)

        elif action == 'r':
            acc_idx, ridx = int(parts[2]), int(parts[3])
            ctx = _user_repo_cache.get(uid, {})
            repos = ctx.get('repos', [])
            if ridx >= len(repos):
                send('❌ Repo not in cache. Use /myrepos to refresh.')
                return
            _send_repo_detail(uid, acc_idx, ridx, repos[ridx], mid)

        elif action == 'tr':
            acc_idx, ridx = int(parts[2]), int(parts[3])
            ctx = _user_repo_cache.get(uid, {})
            repos = ctx.get('repos', [])
            if ridx >= len(repos):
                send('❌ Repo not in cache.')
                return
            repo = repos[ridx]
            acc = _git_store.get_account(uid, acc_idx)
            token = acc['token'] if acc else None
            send(f'Adding <code>{html.escape(repo["full_name"])}</code>…')
            _executor.submit(_add_repo_task, repo['url'], token)

        elif action == 'ri':
            acc_idx, ridx = int(parts[2]), int(parts[3])
            ctx = _user_repo_cache.get(uid, {})
            repos = ctx.get('repos', [])
            if ridx >= len(repos):
                send('❌ Repo not in cache. Use /myrepos to refresh.')
                return
            repo = repos[ridx]
            full_name = repo['full_name']
            owner, repo_name = (full_name.split('/', 1) if '/' in full_name
                                else ('', full_name))
            acc = _git_store.get_account(uid, acc_idx)
            if not acc:
                send('❌ Account not found.')
                return
            from nvd_bot.repos.git_providers import make_provider
            provider = make_provider(acc['type'], acc['base_url'])
            bot.edit_message_text(
                f'🔄 Fetching issues for <b>{html.escape(full_name)}</b>…',
                config.CHAT_ID, mid, parse_mode='HTML')
            _executor.submit(
                _fetch_and_show_issues, uid, provider,
                owner, repo_name, acc['token'], 1, mid,
            )

        elif action == 'rb':
            ctx = _user_repo_cache.get(uid, {})
            acc_idx = ctx.get('acc_idx', 0)
            gh_page = ctx.get('gh_page', 1)
            _executor.submit(_fetch_and_show_repos, uid, acc_idx, gh_page, mid)

        elif action == 'ilp':
            gh_page = int(parts[2])
            ctx = _user_issue_ctx.get(uid)
            if not ctx:
                send('❌ Issue context lost. Please use /issues again.')
                return
            _executor.submit(
                _fetch_and_show_issues, uid, ctx['provider'],
                ctx['owner'], ctx['repo'], ctx['token'], gh_page, mid,
            )

        elif action == 'iv':
            num = int(parts[2])
            ctx = _user_issue_ctx.get(uid)
            if not ctx:
                send('❌ Issue context lost.')
                return
            _executor.submit(
                _show_issue_detail, uid, ctx['provider'],
                ctx['owner'], ctx['repo'], ctx['token'], num, mid,
            )

        elif action == 'ib':
            ctx = _user_issue_ctx.get(uid)
            if not ctx:
                send('❌ Issue context lost.')
                return
            _executor.submit(
                _fetch_and_show_issues, uid, ctx['provider'],
                ctx['owner'], ctx['repo'], ctx['token'], ctx.get('gh_page', 1), mid,
            )

    # ── adm:* callback handler ────────────────────────────────────────────────
    @bot.callback_query_handler(func=lambda call: call.data.startswith('adm:'))
    def handle_adm_callback(call: CallbackQuery):
        if not _authorized(call):
            bot.answer_callback_query(call.id, 'Unauthorized.')
            return
        bot.answer_callback_query(call.id)
        uid = call.from_user.id
        parts = call.data.split(':')
        action = parts[1] if len(parts) > 1 else ''
        mid = call.message.message_id

        if action == 'rm':
            idx = int(parts[2])
            repos = _registry.list_repos()
            if idx >= len(repos):
                bot.edit_message_text('❌ Repo Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            profile = repos[idx]
            ok = _registry.remove_repo(profile.id)
            if ok:
                bot.edit_message_text(
                    f'✅ <b>{html.escape(profile.name)}</b> Removed.',
                    config.CHAT_ID, mid, parse_mode='HTML')
            else:
                bot.edit_message_text('❌ Could Not Remove Repo.', config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'sc':
            idx = int(parts[2])
            repos = _registry.list_repos()
            if idx >= len(repos):
                bot.edit_message_text('❌ Repo Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            profile = repos[idx]
            bot.edit_message_text(
                f'🔄 Scanning <b>{html.escape(profile.name)}</b>…',
                config.CHAT_ID, mid, parse_mode='HTML')
            _executor.submit(_scan_task, profile)

        elif action == 'rmkw':
            idx = int(parts[2])
            kws = config.get('watchlist', [])
            if idx >= len(kws):
                bot.edit_message_text('❌ Keyword Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            kw = kws[idx]
            config.remove_watchlist_keyword(kw)
            bot.edit_message_text(
                f'✅ Keyword Removed: <code>{html.escape(kw)}</code>',
                config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'rmu':
            target_uid = int(parts[2])
            ok = config.remove_allowed_user(target_uid)
            if ok:
                bot.edit_message_text(
                    f'✅ User <code>{target_uid}</code> Removed From Allowlist.',
                    config.CHAT_ID, mid, parse_mode='HTML')
            else:
                bot.edit_message_text(
                    f'❌ User <code>{target_uid}</code> Not Found.',
                    config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'iss':
            idx = int(parts[2])
            repos = _registry.list_repos()
            if idx >= len(repos):
                bot.edit_message_text('❌ Repo Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            profile = repos[idx]
            from nvd_bot.repos.git_providers import make_provider, detect_provider_from_url
            provider_type, base_url = detect_provider_from_url(profile.url)
            acc = _git_store.find_account_for_host(uid, provider_type, base_url)
            token = (acc['token'] if acc else profile.github_token or config.GITHUB_TOKEN)
            if not token:
                bot.edit_message_text(
                    '❌ No Token For This Repo. Connect your account with /connectgit first.',
                    config.CHAT_ID, mid, parse_mode='HTML')
                return
            owner, repo_name = (profile.name.split('/', 1) if '/' in profile.name
                                else ('', profile.name))
            provider = make_provider(provider_type, base_url)
            bot.edit_message_text(
                f'🔄 Fetching Issues For <b>{html.escape(profile.name)}</b>…',
                config.CHAT_ID, mid, parse_mode='HTML')
            _executor.submit(_fetch_and_show_issues, uid, provider, owner, repo_name, token, 1, None)

    # ── Inline keyboard callbacks ─────────────────────────────────────────────
    @bot.callback_query_handler(func=lambda call: call.data.startswith('fix:'))
    def handle_fix_callback(call: CallbackQuery):
        if not _authorized(call):
            bot.answer_callback_query(call.id, 'Unauthorized.')
            return
        try:
            _, action, fix_id = call.data.split(':', 2)
        except ValueError:
            bot.answer_callback_query(call.id, 'Invalid callback.')
            return

        fix = _pending.get(fix_id)
        if not fix:
            bot.answer_callback_query(call.id, 'Fix not found.')
            return

        if fix.status != 'pending':
            bot.answer_callback_query(call.id, f'Already {fix.status}.')
            return

        if action == 'accept':
            bot.answer_callback_query(call.id, '✅ Accepted — creating PR…')
            _pending.update_status(fix_id, 'accepted')
            try:
                bot.edit_message_reply_markup(
                    config.CHAT_ID, call.message.message_id, reply_markup=None)
                bot.edit_message_text(
                    call.message.text + '\n\n⏳ <i>Applying fix…</i>',
                    config.CHAT_ID, call.message.message_id, parse_mode='HTML')
            except Exception:
                pass
            _executor.submit(_apply_fix_task, fix_id)

        elif action == 'deny':
            bot.answer_callback_query(call.id, '❌ Denied.')
            _pending.update_status(fix_id, 'denied')
            try:
                bot.edit_message_reply_markup(
                    config.CHAT_ID, call.message.message_id, reply_markup=None)
                bot.edit_message_text(
                    call.message.text + '\n\n❌ <i>Fix denied.</i>',
                    config.CHAT_ID, call.message.message_id, parse_mode='HTML')
            except Exception:
                pass

        elif action == 'details':
            bot.answer_callback_query(call.id)
            diff = _build_diff_preview(fix.original_content, fix.fixed_content)
            send(
                f'📋 <b>Fix Details</b> — {html.escape(fix.cve_id)}\n\n'
                f'<b>Explanation:</b>\n{html.escape(fix.explanation)}\n\n'
                f'<b>Diff preview:</b>\n<pre>{html.escape(diff)}</pre>'
            )

    def _apply_fix_task(fix_id: str):
        from nvd_bot.repos.scanner import _split_name
        fix = _pending.get(fix_id)
        if not fix:
            return
        profile = _registry.get_repo(fix.repo_id)
        if not profile:
            send(f'❌ Repo {fix.repo_id} not found for fix {fix_id}')
            _pending.update_status(fix_id, 'failed')
            return

        owner, repo = _split_name(profile.name)
        token = profile.github_token
        base_branch = profile.get_config('pr_base_branch', config.get('pr_base_branch', 'main'))
        prefix = profile.get_config('pr_branch_prefix', config.get('pr_branch_prefix', 'security/fix'))
        branch_name = f'{prefix}-{fix.cve_id.lower()}-{fix.fix_id}'

        base_sha = _gh.get_latest_commit_sha(owner, repo, token=token, branch=base_branch)
        if not base_sha:
            send(f'❌ Could not get base SHA for {profile.name}')
            _pending.update_status(fix_id, 'failed')
            return

        _gh.create_branch(owner, repo, branch_name, base_sha, token=token)

        ok = _gh.commit_file(
            owner, repo, fix.file_path, fix.fixed_content,
            message=f'fix: patch {fix.cve_id} — {fix.fix_type}',
            branch=branch_name, token=token,
        )
        if not ok:
            send(f'❌ Failed to commit fix for {fix.cve_id} in {profile.name}')
            _pending.update_status(fix_id, 'failed')
            return

        pr_url = _gh.create_pull_request(
            owner, repo,
            title=f'Security: fix {fix.cve_id} in {fix.file_path}',
            body=(
                f'## Security Fix\n\n'
                f'**CVE:** {fix.cve_id}\n'
                f'**Severity:** {fix.severity}\n'
                f'**File:** `{fix.file_path}`\n\n'
                f'### Explanation\n{fix.explanation}\n\n'
                f'*Generated by NVD Bot*'
            ),
            head=branch_name, base=base_branch, token=token,
        )

        if pr_url:
            _pending.update_status(fix_id, 'applied', pr_url=pr_url)
            send(f'✅ PR created for <b>{html.escape(profile.name)}</b>\n'
                 f'CVE: {html.escape(fix.cve_id)}\n'
                 f'<a href="{html.escape(pr_url)}">View Pull Request</a>')
        else:
            _pending.update_status(fix_id, 'failed')
            send(f'❌ Fix committed but PR creation failed for {fix.cve_id}')


def _pkg_summary(profile) -> str:
    """Return a human-readable package count string for scan messages."""
    count = profile.package_count()
    if count == 0:
        err = getattr(profile, '_llm_scan_error', None)
        if err:
            return f'no dep files found, and LLM inference failed: {err[:200]}'
        return 'no dependency files found (LLM inference found nothing either)'
    suffix = ''
    if 'llm-inferred' in profile.packages:
        suffix = ' (LLM-inferred — verify manually)'
    elif 'import-scan' in profile.packages:
        suffix = ' (from source imports — versions unknown, verify manually)'
    return f'{count} packages found{suffix}'


def _coerce(val: str):
    """Convert string value to appropriate Python type."""
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


def _build_diff_preview(original: str, fixed: str, max_lines: int = 20) -> str:
    orig_lines = original.splitlines()
    fix_lines = fixed.splitlines()
    diff_lines = []
    for i, (o, f) in enumerate(zip(orig_lines, fix_lines)):
        if o != f:
            diff_lines.append(f'- {o}')
            diff_lines.append(f'+ {f}')
        if len(diff_lines) >= max_lines:
            diff_lines.append('...')
            break
    return '\n'.join(diff_lines) if diff_lines else 'No visible changes in preview.'


# ── Git account / repo browser helpers ───────────────────────────────────────

_GIT_ICONS = {'github': '🐙', 'gitlab': '🦊'}


def _start_connect_flow(uid: int, provider_type: str, base_url: str):
    """Kick off the connection flow for the given provider and base URL."""
    _awaiting_token.pop(uid, None)
    _awaiting_url.pop(uid, None)
    if (provider_type == 'github'
            and base_url == 'https://github.com'
            and config.GITHUB_OAUTH_CLIENT_ID
            and config.GITHUB_OAUTH_CLIENT_SECRET):
        try:
            from nvd_bot.repos.device_flow import start as df_start
            data = df_start(config.GITHUB_OAUTH_CLIENT_ID)
            send(
                f'🔑 <b>GitHub Login</b>\n\n'
                f'1. Visit: <a href="{html.escape(data["verification_uri"])}">'
                f'{html.escape(data["verification_uri"])}</a>\n'
                f'2. Enter this code:\n\n'
                f'<code>{html.escape(data["user_code"])}</code>\n\n'
                f'Waiting for authorization… (expires in {data["expires_in"] // 60} min)'
            )
            _executor.submit(
                _oauth_poll_task, uid, provider_type, base_url,
                data['device_code'], data['interval'], data['expires_in'],
            )
        except Exception as e:
            send(f'❌ Device flow error: {html.escape(str(e))}\n\nFalling back to PAT…')
            _send_pat_instructions(uid, provider_type, base_url)
        return
    _send_pat_instructions(uid, provider_type, base_url)


def _send_pat_instructions(uid: int, provider_type: str, base_url: str):
    """Store awaiting-token state and send PAT creation instructions to CHAT_ID."""
    _awaiting_token[uid] = {'provider_type': provider_type, 'base_url': base_url}
    if provider_type == 'github':
        if base_url == 'https://github.com':
            pat_url = 'https://github.com/settings/tokens/new?scopes=repo,read:user'
        else:
            pat_url = f'{base_url}/settings/tokens/new'
        send(
            f'🔑 <b>GitHub Personal Access Token</b>\n\n'
            f'Create a token at:\n<code>{html.escape(pat_url)}</code>\n\n'
            f'Required scopes: <code>repo</code>, <code>read:user</code>\n\n'
            f'Then paste the token here.\n'
            f'⚠️ The message will be deleted from the chat immediately.'
        )
    else:
        if base_url == 'https://gitlab.com':
            pat_url = 'https://gitlab.com/-/user_settings/personal_access_tokens'
        else:
            pat_url = f'{base_url}/-/user_settings/personal_access_tokens'
        send(
            f'🔑 <b>GitLab Personal Access Token</b>\n\n'
            f'Create a token at:\n<code>{html.escape(pat_url)}</code>\n\n'
            f'Required scopes: <code>read_api</code>, <code>read_user</code>\n\n'
            f'Then paste the token here.\n'
            f'⚠️ The message will be deleted from the chat immediately.'
        )


def _oauth_poll_task(uid: int, provider_type: str, base_url: str,
                     device_code: str, interval: int, expires_in: int):
    """Background: poll GitHub Device Flow until authorized or expired."""
    import time
    from nvd_bot.repos.device_flow import poll_token
    from nvd_bot.repos.git_providers import GitHubProvider
    elapsed = 0
    poll_interval = max(interval, 5)
    while elapsed < expires_in:
        time.sleep(poll_interval)
        elapsed += poll_interval
        try:
            token = poll_token(
                config.GITHUB_OAUTH_CLIENT_ID,
                config.GITHUB_OAUTH_CLIENT_SECRET,
                device_code, base_url,
            )
        except RuntimeError as e:
            send(f'❌ GitHub authorization {html.escape(str(e))}. Please try /connectgit again.')
            return
        if token:
            provider = GitHubProvider(base_url)
            info = provider.get_user_info(token)
            username = info['username'] if info else 'unknown'
            _git_store.add_account(uid, provider_type, base_url, token, username)
            send(
                f'✅ Connected as <b>@{html.escape(username)}</b> on {html.escape(base_url)}!\n\n'
                f'Use /myrepos to browse your repositories.'
            )
            return
    send('❌ GitHub authorization timed out. Please try /connectgit again.')


def _fetch_and_show_repos(uid: int, acc_idx: int, gh_page: int, edit_msg_id):
    """Fetch one page of repos for account acc_idx and render the browser."""
    from nvd_bot.repos.git_providers import make_provider
    acc = _git_store.get_account(uid, acc_idx)
    if not acc:
        send(f'❌ Account #{acc_idx} not found.')
        return
    provider = make_provider(acc['type'], acc['base_url'])
    try:
        repos = provider.list_user_repos(acc['token'], page=gh_page, per_page=8)
    except Exception as e:
        send(f'❌ Failed to fetch repos: {html.escape(str(e))}')
        return
    _user_repo_cache[uid] = {
        'acc_idx': acc_idx,
        'gh_page': gh_page,
        'repos': repos,
        'has_more': len(repos) == 8,
    }
    _send_repo_browser(uid, edit_msg_id=edit_msg_id)


def _send_repo_browser(uid: int, edit_msg_id=None):
    ctx = _user_repo_cache.get(uid)
    if not ctx or not ctx['repos']:
        text = 'No repositories found on this page. Try /myrepos to start over.'
        _edit_or_send(text, None, edit_msg_id)
        return

    acc_idx = ctx['acc_idx']
    gh_page = ctx['gh_page']
    repos = ctx['repos']
    has_more = ctx['has_more']

    acc = _git_store.get_account(uid, acc_idx)
    acc_icon = _GIT_ICONS.get(acc['type'], '🔗') if acc else '🔗'
    acc_name = acc['username'] if acc else f'#{acc_idx}'

    kb = InlineKeyboardMarkup()
    for i, repo in enumerate(repos):
        lock = '🔒' if repo.get('private') else '📦'
        label = f'{lock} {repo["full_name"]}'
        if len(label) > 45:
            label = label[:42] + '…'
        kb.add(InlineKeyboardButton(label, callback_data=f'gh:r:{acc_idx}:{i}'))

    nav = []
    if gh_page > 1:
        nav.append(InlineKeyboardButton('◀', callback_data=f'gh:rp:{acc_idx}:{gh_page-1}'))
    nav.append(InlineKeyboardButton(f'Page {gh_page}', callback_data='gh:nop'))
    if has_more:
        nav.append(InlineKeyboardButton('▶', callback_data=f'gh:rp:{acc_idx}:{gh_page+1}'))
    if nav:
        kb.row(*nav)

    text = f'{acc_icon} <b>{html.escape(acc_name)}\'s Repositories</b> — page {gh_page}\n\nTap a repo to see options.'
    _edit_or_send(text, kb, edit_msg_id)


def _send_repo_detail(uid: int, acc_idx: int, ridx: int, repo: dict, edit_msg_id=None):
    full_name = repo['full_name']
    desc = (repo.get('description') or 'No description')[:200]
    lock = '🔒 Private' if repo.get('private') else '🔓 Public'
    open_issues = repo.get('open_issues', 0)
    url = repo.get('url', '')

    text = (
        f'📦 <b>{html.escape(full_name)}</b>\n\n'
        f'{lock}\n'
        f'📝 {html.escape(desc)}\n'
        f'🐛 Open issues: {open_issues}\n'
        + (f'🔗 <a href="{html.escape(url)}">{html.escape(url)}</a>' if url else '')
    )
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton('➕ Track', callback_data=f'gh:tr:{acc_idx}:{ridx}'),
        InlineKeyboardButton('🐛 Issues', callback_data=f'gh:ri:{acc_idx}:{ridx}'),
    )
    kb.add(InlineKeyboardButton('← Back to repos', callback_data='gh:rb'))
    _edit_or_send(text, kb, edit_msg_id, disable_web_page_preview=True)


def _fetch_and_show_issues(uid: int, provider, owner: str, repo: str,
                            token: str, gh_page: int, edit_msg_id=None):
    try:
        issues = provider.list_issues(owner, repo, token, page=gh_page, per_page=8)
    except Exception as e:
        send(f'❌ Failed to fetch issues: {html.escape(str(e))}')
        return
    _user_issue_ctx[uid] = {
        'provider': provider,
        'owner': owner,
        'repo': repo,
        'token': token,
        'issues': issues,
        'gh_page': gh_page,
        'has_more': len(issues) == 8,
    }
    _send_issue_list(uid, edit_msg_id)


def _send_issue_list(uid: int, edit_msg_id=None):
    ctx = _user_issue_ctx.get(uid)
    if not ctx:
        _edit_or_send('❌ Issue context lost. Please use /issues &lt;repo-id&gt; again.', None, edit_msg_id)
        return

    owner, repo = ctx['owner'], ctx['repo']
    issues = ctx['issues']
    gh_page = ctx['gh_page']
    has_more = ctx['has_more']

    if not issues:
        _edit_or_send(
            f'No open issues in <b>{html.escape(owner)}/{html.escape(repo)}</b>.',
            None, edit_msg_id,
        )
        return

    kb = InlineKeyboardMarkup()
    for issue in issues:
        state_icon = '🟢' if issue['state'] in ('open', 'opened') else '🔴'
        label = f'{state_icon} #{issue["number"]} {issue["title"]}'
        if len(label) > 50:
            label = label[:47] + '…'
        kb.add(InlineKeyboardButton(label, callback_data=f'gh:iv:{issue["number"]}'))

    nav = []
    if gh_page > 1:
        nav.append(InlineKeyboardButton('◀', callback_data=f'gh:ilp:{gh_page-1}'))
    nav.append(InlineKeyboardButton(f'Page {gh_page}', callback_data='gh:nop'))
    if has_more:
        nav.append(InlineKeyboardButton('▶', callback_data=f'gh:ilp:{gh_page+1}'))
    if nav:
        kb.row(*nav)

    text = f'🐛 <b>Issues — {html.escape(owner)}/{html.escape(repo)}</b> (page {gh_page})'
    _edit_or_send(text, kb, edit_msg_id)


def _show_issue_detail(uid: int, provider, owner: str, repo: str,
                        token: str, number: int, edit_msg_id=None):
    try:
        issue = provider.get_issue(owner, repo, number, token)
    except Exception as e:
        send(f'❌ Failed to fetch issue: {html.escape(str(e))}')
        return
    if not issue:
        send(f'❌ Issue #{number} not found.')
        return

    state_icon = '🟢' if issue['state'] in ('open', 'opened') else '🔴'
    labels_str = '  '.join(f'[{html.escape(l)}]' for l in issue.get('labels', []))
    body = (issue.get('body') or '').strip()
    body_preview = body[:1000] + ('\n<i>[truncated]</i>' if len(body) > 1000 else '')

    text = (
        f'{state_icon} <b>#{issue["number"]}: {html.escape(issue["title"])}</b>\n'
        f'<b>{html.escape(owner)}/{html.escape(repo)}</b>\n'
        + (f'{labels_str}\n' if labels_str else '')
        + f'👤 {html.escape(issue.get("author", ""))} · {html.escape(issue.get("created_at", ""))}\n'
        f'🔗 <a href="{html.escape(issue.get("url", ""))}">Open in browser</a>\n\n'
        + (f'<pre>{html.escape(body_preview)}</pre>' if body_preview else '<i>No description.</i>')
    )
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton('← Back to issues', callback_data='gh:ib'))
    _edit_or_send(text, kb, edit_msg_id, disable_web_page_preview=True)


def _edit_or_send(text: str, kb, edit_msg_id=None, disable_web_page_preview: bool = False):
    """Edit an existing message in place, or send a new one if not possible."""
    if edit_msg_id:
        try:
            bot.edit_message_text(
                text, config.CHAT_ID, edit_msg_id,
                parse_mode='HTML', reply_markup=kb,
                disable_web_page_preview=disable_web_page_preview,
            )
            return
        except Exception:
            pass
    send(text, reply_markup=kb)
