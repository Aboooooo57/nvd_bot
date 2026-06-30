"""Callbacks for admin actions: adm:rm, adm:sc, adm:rmkw, adm:rmu, adm:iss."""
from __future__ import annotations
import html

from telebot.types import CallbackQuery

from nvd_bot import config
from nvd_bot.bot import state


def register():
    @state.bot.callback_query_handler(func=lambda call: call.data.startswith('adm:'))
    def handle_adm_callback(call: CallbackQuery):
        if not _authorized(call):
            state.bot.answer_callback_query(call.id, 'Unauthorized.')
            return
        state.bot.answer_callback_query(call.id)
        uid = call.from_user.id
        parts = call.data.split(':')
        action = parts[1] if len(parts) > 1 else ''
        mid = call.message.message_id

        if action == 'rm':
            idx = int(parts[2])
            repos = state._registry.list_repos()
            if idx >= len(repos):
                state.bot.edit_message_text('❌ Repo Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            profile = repos[idx]
            ok = state._registry.remove_repo(profile.id)
            if ok:
                state.bot.edit_message_text(
                    f'✅ <b>{html.escape(profile.name)}</b> Removed.',
                    config.CHAT_ID, mid, parse_mode='HTML')
            else:
                state.bot.edit_message_text('❌ Could Not Remove Repo.', config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'sc':
            idx = int(parts[2])
            repos = state._registry.list_repos()
            if idx >= len(repos):
                state.bot.edit_message_text('❌ Repo Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            profile = repos[idx]
            state.bot.edit_message_text(
                f'🔄 Scanning <b>{html.escape(profile.name)}</b>…',
                config.CHAT_ID, mid, parse_mode='HTML')
            from nvd_bot.bot.handlers.repos import _scan_task
            state._executor.submit(_scan_task, profile)

        elif action == 'rmkw':
            idx = int(parts[2])
            kws = config.get('watchlist', [])
            if idx >= len(kws):
                state.bot.edit_message_text('❌ Keyword Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            kw = kws[idx]
            config.remove_watchlist_keyword(kw)
            state.bot.edit_message_text(
                f'✅ Keyword Removed: <code>{html.escape(kw)}</code>',
                config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'rmu':
            target_uid = int(parts[2])
            ok = config.remove_allowed_user(target_uid)
            if ok:
                state.bot.edit_message_text(
                    f'✅ User <code>{target_uid}</code> Removed From Allowlist.',
                    config.CHAT_ID, mid, parse_mode='HTML')
            else:
                state.bot.edit_message_text(
                    f'❌ User <code>{target_uid}</code> Not Found.',
                    config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'iss':
            idx = int(parts[2])
            repos = state._registry.list_repos()
            if idx >= len(repos):
                state.bot.edit_message_text('❌ Repo Not Found.', config.CHAT_ID, mid, parse_mode='HTML')
                return
            profile = repos[idx]
            from nvd_bot.repos.git_providers import make_provider, detect_provider_from_url
            provider_type, base_url = detect_provider_from_url(profile.url)
            acc = state._git_store.find_account_for_host(uid, provider_type, base_url)
            token = acc['token'] if acc else profile.github_token or config.GITHUB_TOKEN
            if not token:
                state.bot.edit_message_text(
                    '❌ No Token For This Repo. Connect your account with /connectgit first.',
                    config.CHAT_ID, mid, parse_mode='HTML')
                return
            owner, repo_name = (profile.name.split('/', 1) if '/' in profile.name
                                else ('', profile.name))
            provider = make_provider(provider_type, base_url)
            state.bot.edit_message_text(
                f'🔄 Fetching Issues For <b>{html.escape(profile.name)}</b>…',
                config.CHAT_ID, mid, parse_mode='HTML')
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_issues
            state._executor.submit(fetch_and_show_issues, uid, provider, owner, repo_name, token, 1, None)


def _authorized(call) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(call)
