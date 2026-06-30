"""Handlers for repo management commands: /addrepo, /removerepo, /listrepos, /scanrepo, /repoprofile, /setrepo."""
from __future__ import annotations
import html
import json

from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Message

from nvd_bot.bot import state
from nvd_bot.bot.utils import send, pkg_summary, coerce


def register():
    @state.bot.message_handler(commands=['addrepo'])
    def cmd_addrepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=2)
        if len(parts) < 2:
            send('Usage: /addrepo &lt;github-url&gt; [optional-token]')
            return
        url = parts[1].strip()
        token = parts[2].strip() if len(parts) > 2 else None
        send(f'Adding repo <code>{html.escape(url)}</code>…')
        state._executor.submit(_add_repo_task, url, token)

    @state.bot.message_handler(commands=['removerepo'])
    def cmd_removerepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split()
        if len(parts) < 2:
            repos = state._registry.list_repos()
            if not repos:
                send('No Repos Tracked Yet. Use /addrepo to add one.')
                return
            kb = InlineKeyboardMarkup()
            for i, p in enumerate(repos):
                kb.add(InlineKeyboardButton(f'🗑 {p.name}', callback_data=f'adm:rm:{i}'))
            send('<b>Select Repo to Remove:</b>', reply_markup=kb)
            return
        ok = state._registry.remove_repo(parts[1].strip())
        if ok:
            send(f'✅ Repo <code>{html.escape(parts[1].strip())}</code> Removed.')
        else:
            send(f'❌ Repo ID <code>{html.escape(parts[1].strip())}</code> Not Found.')

    @state.bot.message_handler(commands=['listrepos'])
    def cmd_listrepos(msg: Message):
        if not _authorized(msg): return
        repos = state._registry.list_repos()
        if not repos:
            send('No repos tracked yet. Use /addrepo &lt;url&gt; to add one.')
            return
        lines = ['<b>Tracked Repositories</b>\n']
        for p in repos:
            status = '✅' if p.enabled else '⏸'
            lines.append(
                f'{status} <b>{html.escape(p.name)}</b>\n'
                f'   ID: <code>{p.id}</code>\n'
                f'   Lang: {p.language} | Pkgs: {p.package_count()} | '
                f'Last scan: {(p.last_scanned_at or "never")[:10]}'
            )
        send('\n\n'.join(lines))

    @state.bot.message_handler(commands=['scanrepo'])
    def cmd_scanrepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split()
        if len(parts) < 2:
            repos = state._registry.list_repos()
            if not repos:
                send('No Repos Tracked Yet. Use /addrepo to add one.')
                return
            kb = InlineKeyboardMarkup()
            for i, p in enumerate(repos):
                kb.add(InlineKeyboardButton(f'🔄 {p.name}', callback_data=f'adm:sc:{i}'))
            send('<b>Select Repo to Scan:</b>', reply_markup=kb)
            return
        profile = state._registry.get_repo(parts[1].strip())
        if not profile:
            send(f'❌ Repo <code>{html.escape(parts[1].strip())}</code> Not Found.')
            return
        send(f'🔄 Scanning <b>{html.escape(profile.name)}</b>…')
        state._executor.submit(_scan_task, profile)

    @state.bot.message_handler(commands=['repoprofile'])
    def cmd_repoprofile(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split()
        if len(parts) < 2:
            send('Usage: /repoprofile &lt;repo-id&gt;')
            return
        profile = state._registry.get_repo(parts[1].strip())
        if not profile:
            send('❌ Repo not found.')
            return
        safe = profile.to_dict()
        safe.pop('github_token', None)
        send(f'<b>{html.escape(profile.name)}</b>\n\n<pre>{html.escape(json.dumps(safe, indent=2))}</pre>')

    @state.bot.message_handler(commands=['setrepo'])
    def cmd_setrepo(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=3)
        if len(parts) < 4:
            send('Usage: /setrepo &lt;repo-id&gt; &lt;key&gt; &lt;value&gt;\n'
                 'Example: /setrepo abc123 enabled true')
            return
        repo_id, key, raw_val = parts[1], parts[2], parts[3]
        profile = state._registry.get_repo(repo_id)
        if not profile:
            send(f'❌ Repo <code>{html.escape(repo_id)}</code> not found.')
            return
        val = coerce(raw_val)
        if hasattr(profile, key) and key not in ('id', 'name', 'url'):
            setattr(profile, key, val)
        else:
            profile.set_override(key, val)
        state._registry.update_profile(profile)
        send(f'✅ <b>{html.escape(profile.name)}</b>: <code>{key}</code> = <code>{html.escape(str(val))}</code>')


def _add_repo_task(url: str, token: str | None):
    from nvd_bot.repos.scanner import scan_repo
    try:
        profile = state._registry.add_repo(url, github_token=token)
        send(f'✅ Repo added: <b>{html.escape(profile.name)}</b>\nID: <code>{profile.id}</code>\nScanning packages…')
        scan_repo(profile, state._gh, state._llm)
        state._registry.update_profile(profile)
        send(f'📦 Scan complete for <b>{html.escape(profile.name)}</b>: '
             f'{pkg_summary(profile)}, language: {profile.language}')
    except Exception as e:
        send(f'❌ Error adding repo: {html.escape(str(e))}')


def _scan_task(profile):
    from nvd_bot.repos.scanner import scan_repo
    try:
        scan_repo(profile, state._gh, state._llm)
        state._registry.update_profile(profile)
        send(f'✅ Scan done: <b>{html.escape(profile.name)}</b> — '
             f'{pkg_summary(profile)}, language: {profile.language}')
    except Exception as e:
        send(f'❌ Scan failed: {html.escape(str(e))}')


def _authorized(msg) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(msg)
