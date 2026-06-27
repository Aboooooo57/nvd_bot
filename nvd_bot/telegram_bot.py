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

bot: telebot.TeleBot = None  # initialized in init()
_executor = ThreadPoolExecutor(max_workers=4)

# Shared references injected by main.py
_registry: RepoRegistry = None
_pending: PendingFixStore = None
_gh: GithubClient = None
_llm: LLMClient = None


def init(registry, pending, gh, llm):
    global bot, _registry, _pending, _gh, _llm
    _registry = registry
    _pending = pending
    _gh = gh
    _llm = llm
    bot = telebot.TeleBot(config.TELEGRAM_BOT_TOKEN, parse_mode='HTML')
    _register_handlers()
    try:
        bot.set_my_commands([
            BotCommand('addrepo',       'Track a GitHub repo'),
            BotCommand('removerepo',    'Stop tracking a repo'),
            BotCommand('listrepos',     'List all tracked repos'),
            BotCommand('scanrepo',      'Force re-scan a repo now'),
            BotCommand('repoprofile',   'Show full repo profile JSON'),
            BotCommand('setrepo',       'Set a per-repo config override'),
            BotCommand('pending',       'List pending fix proposals'),
            BotCommand('settings',      'Show all current settings'),
            BotCommand('setconfig',     'Update a config value live'),
            BotCommand('addkeyword',    'Add a CVE watchlist keyword'),
            BotCommand('removekeyword', 'Remove a watchlist keyword'),
            BotCommand('llmcheck',      'Test LLM connection'),
            BotCommand('status',        'System status overview'),
            BotCommand('help',          'Show all commands'),
            BotCommand('adduser',       'Allow a user (owner only)'),
            BotCommand('removeuser',    'Remove a user (owner only)'),
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
            send('Usage: /removerepo &lt;repo-id&gt;')
            return
        repo_id = parts[1].strip()
        ok = _registry.remove_repo(repo_id)
        if ok:
            send(f'✅ Repo <code>{repo_id}</code> removed.')
        else:
            send(f'❌ Repo ID <code>{repo_id}</code> not found.')

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
            send('Usage: /scanrepo &lt;repo-id&gt;')
            return
        repo_id = parts[1].strip()
        profile = _registry.get_repo(repo_id)
        if not profile:
            send(f'❌ Repo <code>{repo_id}</code> not found.')
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
            send('Usage: /removekeyword &lt;word&gt;')
            return
        word = parts[1].strip().lower()
        ok = config.remove_watchlist_keyword(word)
        if ok:
            send(f'✅ Removed keyword: <code>{html.escape(word)}</code>')
        else:
            send(f'❌ Keyword not found: <code>{html.escape(word)}</code>')

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
            send('Usage: /removeuser &lt;telegram-user-id&gt;')
            return
        uid = int(parts[1])
        ok = config.remove_allowed_user(uid)
        if ok:
            send(f'✅ User <code>{uid}</code> removed from allowlist.')
        else:
            send(f'❌ User <code>{uid}</code> not found in allowlist.')

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
            '/removeuser &lt;id&gt; — Remove a user from the allowlist'
        )

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
