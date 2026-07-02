"""Callbacks for all gh:* actions: account select, repo browser, track, issues."""
from __future__ import annotations
import html

from telebot.types import CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton

from nvd_bot import config
from nvd_bot.bot import state


def register():
    @state.bot.callback_query_handler(func=lambda call: call.data.startswith('gh:'))
    def handle_gh_callback(call: CallbackQuery):
        if not _authorized(call):
            state.bot.answer_callback_query(call.id, 'Unauthorized.')
            return
        state.bot.answer_callback_query(call.id)
        uid = call.from_user.id
        parts = call.data.split(':')
        action = parts[1] if len(parts) > 1 else ''
        mid = call.message.message_id

        if action == 'nop':
            return

        elif action == 'cg':
            _handle_cg(uid, mid, parts)

        elif action == 'rmac':
            idx = int(parts[2])
            ok = state._git_store.remove_account(uid, idx)
            if ok:
                state.bot.edit_message_text('✅ Account Disconnected.', config.CHAT_ID, mid, parse_mode='HTML')
            else:
                state.bot.edit_message_text('❌ Account Not Found.', config.CHAT_ID, mid, parse_mode='HTML')

        elif action == 'acc':
            acc_idx = int(parts[2])
            acc = state._git_store.get_account(uid, acc_idx)
            if acc:
                state.bot.edit_message_text(
                    f'🔄 Fetching repos for <b>{html.escape(acc["username"])}</b>…',
                    config.CHAT_ID, mid, parse_mode='HTML')
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_repos
            state._executor.submit(fetch_and_show_repos, uid, acc_idx, 1, mid)

        elif action == 'rp':
            acc_idx, gh_page = int(parts[2]), int(parts[3])
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_repos
            state._executor.submit(fetch_and_show_repos, uid, acc_idx, gh_page, mid)

        elif action == 'r':
            acc_idx, ridx = int(parts[2]), int(parts[3])
            ctx = state._user_repo_cache.get(uid, {})
            repos = ctx.get('repos', [])
            if ridx >= len(repos):
                state.bot.send_message(config.CHAT_ID,
                                       '❌ Repo not in cache. Use /myrepos to refresh.', parse_mode='HTML')
                return
            from nvd_bot.bot.handlers.git_browser import send_repo_detail
            send_repo_detail(uid, acc_idx, ridx, repos[ridx], mid)

        elif action == 'tr':
            acc_idx, ridx = int(parts[2]), int(parts[3])
            ctx = state._user_repo_cache.get(uid, {})
            repos = ctx.get('repos', [])
            if ridx >= len(repos):
                state.bot.send_message(config.CHAT_ID, '❌ Repo not in cache.', parse_mode='HTML')
                return
            repo = repos[ridx]
            acc = state._git_store.get_account(uid, acc_idx)
            token = acc['token'] if acc else None
            from nvd_bot.bot.utils import send
            from nvd_bot.bot.handlers.repos import _add_repo_task
            send(f'Adding <code>{html.escape(repo["full_name"])}</code>…')
            state._executor.submit(_add_repo_task, repo['url'], token)

        elif action == 'ri':
            acc_idx, ridx = int(parts[2]), int(parts[3])
            ctx = state._user_repo_cache.get(uid, {})
            repos = ctx.get('repos', [])
            if ridx >= len(repos):
                state.bot.send_message(config.CHAT_ID,
                                       '❌ Repo not in cache. Use /myrepos to refresh.', parse_mode='HTML')
                return
            repo = repos[ridx]
            full_name = repo['full_name']
            owner, repo_name = (full_name.split('/', 1) if '/' in full_name else ('', full_name))
            acc = state._git_store.get_account(uid, acc_idx)
            if not acc:
                state.bot.send_message(config.CHAT_ID, '❌ Account not found.', parse_mode='HTML')
                return
            from nvd_bot.repos.git_providers import make_provider
            provider = make_provider(acc['type'], acc['base_url'])
            state.bot.edit_message_text(
                f'🔄 Fetching issues for <b>{html.escape(full_name)}</b>…',
                config.CHAT_ID, mid, parse_mode='HTML')
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_issues
            state._executor.submit(fetch_and_show_issues, uid, provider,
                                   owner, repo_name, acc['token'], 1, mid)

        elif action == 'rb':
            ctx = state._user_repo_cache.get(uid, {})
            acc_idx = ctx.get('acc_idx', 0)
            gh_page = ctx.get('gh_page', 1)
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_repos
            state._executor.submit(fetch_and_show_repos, uid, acc_idx, gh_page, mid)

        elif action == 'ilp':
            gh_page = int(parts[2])
            ctx = state._user_issue_ctx.get(uid)
            if not ctx:
                state.bot.send_message(config.CHAT_ID,
                                       '❌ Issue context lost. Please use /issues again.', parse_mode='HTML')
                return
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_issues
            state._executor.submit(fetch_and_show_issues, uid, ctx['provider'],
                                   ctx['owner'], ctx['repo'], ctx['token'], gh_page, mid)

        elif action == 'iv':
            num = int(parts[2])
            ctx = state._user_issue_ctx.get(uid)
            if not ctx:
                state.bot.send_message(config.CHAT_ID, '❌ Issue context lost.', parse_mode='HTML')
                return
            from nvd_bot.bot.handlers.git_browser import show_issue_detail
            state._executor.submit(show_issue_detail, uid, ctx['provider'],
                                   ctx['owner'], ctx['repo'], ctx['token'], num, mid)

        elif action == 'ib':
            ctx = state._user_issue_ctx.get(uid)
            if not ctx:
                state.bot.send_message(config.CHAT_ID, '❌ Issue context lost.', parse_mode='HTML')
                return
            from nvd_bot.bot.handlers.git_browser import fetch_and_show_issues
            state._executor.submit(fetch_and_show_issues, uid, ctx['provider'],
                                   ctx['owner'], ctx['repo'], ctx['token'], ctx.get('gh_page', 1), mid)


def _handle_cg(uid: int, mid: int, parts: list):
    from nvd_bot.bot.handlers.git_connect import start_connect_flow
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
        state.bot.edit_message_text('<b>Connect a Git Account</b>\n\nChoose a Provider:',
                                    config.CHAT_ID, mid, reply_markup=kb, parse_mode='HTML')
    elif choice == 'gh':
        state.bot.edit_message_text('<b>Connect GitHub</b>\n\n🔄 Starting…',
                                    config.CHAT_ID, mid, parse_mode='HTML')
        state._executor.submit(start_connect_flow, uid, 'github', 'https://github.com')
    elif choice == 'gl':
        state.bot.edit_message_text('<b>Connect GitLab</b>\n\n🔄 Starting…',
                                    config.CHAT_ID, mid, parse_mode='HTML')
        state._executor.submit(start_connect_flow, uid, 'gitlab', 'https://gitlab.com')
    elif choice in ('ghe', 'gls'):
        provider_type = 'github' if choice == 'ghe' else 'gitlab'
        example = ('https://github.mycompany.com' if choice == 'ghe'
                   else 'https://gitlab.mycompany.com')
        state._awaiting_url[uid] = {'provider_type': provider_type}
        state.bot.edit_message_text(
            f'Enter Your Self-Hosted URL:\n<code>{html.escape(example)}</code>',
            config.CHAT_ID, mid, parse_mode='HTML')


def _authorized(call) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(call)
