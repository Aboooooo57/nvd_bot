"""Handlers for git connect commands: /connectgit, /disconnectgit, /gitaccounts + PAT/URL paste."""
from __future__ import annotations
import html

from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Message

from nvd_bot import config
from nvd_bot.bot import state
from nvd_bot.bot.utils import send, _GIT_ICONS


def register():
    @state.bot.message_handler(
        func=lambda m: (m.from_user and m.from_user.id in state._awaiting_token
                        and m.text and not m.text.startswith('/'))
    )
    def handle_token_paste(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        ctx = state._awaiting_token.pop(uid, None)
        if not ctx:
            return
        try:
            state.bot.delete_message(msg.chat.id, msg.message_id)
        except Exception:
            pass
        token = msg.text.strip()
        from nvd_bot.repos.git_providers import make_provider
        provider = make_provider(ctx['provider_type'], ctx['base_url'])
        try:
            info = provider.get_user_info(token)
        except Exception as e:
            state._awaiting_token[uid] = ctx
            send(f'❌ Token validation failed: {html.escape(str(e))}\nPlease try again.')
            return
        if not info:
            state._awaiting_token[uid] = ctx
            send('❌ Invalid token or insufficient permissions. Please check and try again.')
            return
        username = info.get('username', 'unknown')
        state._git_store.add_account(uid, ctx['provider_type'], ctx['base_url'], token, username)
        send(
            f'✅ Connected as <b>{html.escape(username)}</b> on '
            f'{html.escape(ctx["base_url"])}!\n\nUse /myrepos to browse your repositories.'
        )

    @state.bot.message_handler(
        func=lambda m: (m.from_user and m.from_user.id in state._awaiting_url
                        and m.text and not m.text.startswith('/'))
    )
    def handle_url_paste(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        ctx = state._awaiting_url.pop(uid, None)
        if not ctx:
            return
        raw = msg.text.strip()
        if not raw.startswith('http'):
            state._awaiting_url[uid] = ctx
            send('❌ Please enter a valid URL starting with <code>https://</code>')
            return
        start_connect_flow(uid, ctx['provider_type'], raw.rstrip('/'))

    @state.bot.message_handler(commands=['connectgit'])
    def cmd_connectgit(msg: Message):
        if not _authorized(msg): return
        parts = msg.text.split(maxsplit=2)
        uid = msg.from_user.id
        if len(parts) < 2:
            kb = InlineKeyboardMarkup()
            kb.row(
                InlineKeyboardButton('🐙 GitHub', callback_data='gh:cg:gh'),
                InlineKeyboardButton('🦊 GitLab', callback_data='gh:cg:gl'),
            )
            kb.row(
                InlineKeyboardButton('⚙️ GitHub Enterprise', callback_data='gh:cg:ghe'),
                InlineKeyboardButton('⚙️ GitLab Self-hosted', callback_data='gh:cg:gls'),
            )
            state.bot.send_message(config.CHAT_ID, '<b>Connect a Git account</b>\n\nChoose a provider:',
                                   reply_markup=kb, parse_mode='HTML')
            return
        provider_type = parts[1].strip().lower()
        if provider_type not in ('github', 'gitlab'):
            send('❌ Type must be <code>github</code> or <code>gitlab</code>.')
            return
        base_url = (parts[2].strip() if len(parts) > 2
                    else ('https://github.com' if provider_type == 'github' else 'https://gitlab.com'))
        start_connect_flow(uid, provider_type, base_url.rstrip('/'))

    @state.bot.message_handler(commands=['disconnectgit'])
    def cmd_disconnectgit(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        parts = msg.text.split()
        if len(parts) < 2 or not parts[1].isdigit():
            show_gitaccounts(uid)
            return
        idx = int(parts[1])
        ok = state._git_store.remove_account(uid, idx)
        if ok:
            send(f'✅ Account #{idx} Disconnected.')
        else:
            send(f'❌ Account #{idx} Not Found.')

    @state.bot.message_handler(commands=['gitaccounts'])
    def cmd_gitaccounts(msg: Message):
        if not _authorized(msg): return
        show_gitaccounts(msg.from_user.id)


def show_gitaccounts(uid: int):
    accounts = state._git_store.list_accounts(uid)
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


def start_connect_flow(uid: int, provider_type: str, base_url: str):
    """Kick off the connection flow for the given provider and base URL."""
    state._awaiting_token.pop(uid, None)
    state._awaiting_url.pop(uid, None)
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
            state._executor.submit(
                _oauth_poll_task, uid, provider_type, base_url,
                data['device_code'], data['interval'], data['expires_in'],
            )
        except Exception as e:
            send(f'❌ Device flow error: {html.escape(str(e))}\n\nFalling back to PAT…')
            _send_pat_instructions(uid, provider_type, base_url)
        return
    _send_pat_instructions(uid, provider_type, base_url)


def _send_pat_instructions(uid: int, provider_type: str, base_url: str):
    state._awaiting_token[uid] = {'provider_type': provider_type, 'base_url': base_url}
    if provider_type == 'github':
        pat_url = ('https://github.com/settings/tokens/new?scopes=repo,read:user'
                   if base_url == 'https://github.com' else f'{base_url}/settings/tokens/new')
        send(
            f'🔑 <b>GitHub Personal Access Token</b>\n\n'
            f'Create a token at:\n<code>{html.escape(pat_url)}</code>\n\n'
            f'Required scopes: <code>repo</code>, <code>read:user</code>\n\n'
            f'Then paste the token here.\n'
            f'⚠️ The message will be deleted from the chat immediately.'
        )
    else:
        pat_url = ('https://gitlab.com/-/user_settings/personal_access_tokens'
                   if base_url == 'https://gitlab.com'
                   else f'{base_url}/-/user_settings/personal_access_tokens')
        send(
            f'🔑 <b>GitLab Personal Access Token</b>\n\n'
            f'Create a token at:\n<code>{html.escape(pat_url)}</code>\n\n'
            f'Required scopes: <code>read_api</code>, <code>read_user</code>\n\n'
            f'Then paste the token here.\n'
            f'⚠️ The message will be deleted from the chat immediately.'
        )


def _oauth_poll_task(uid: int, provider_type: str, base_url: str,
                     device_code: str, interval: int, expires_in: int):
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
            state._git_store.add_account(uid, provider_type, base_url, token, username)
            send(
                f'✅ Connected as <b>@{html.escape(username)}</b> on {html.escape(base_url)}!\n\n'
                f'Use /myrepos to browse your repositories.'
            )
            return
    send('❌ GitHub authorization timed out. Please try /connectgit again.')


def _authorized(msg) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(msg)
