"""Handlers for git browser commands: /myrepos, /issues + all browser helpers."""
from __future__ import annotations
import html

from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Message

from nvd_bot import config
from nvd_bot.bot import state
from nvd_bot.bot.utils import send, edit_or_send, _GIT_ICONS


def register():
    @state.bot.message_handler(commands=['myrepos'])
    def cmd_myrepos(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        accounts = state._git_store.list_accounts(uid)
        if not accounts:
            send('No git accounts connected. Use /connectgit &lt;github|gitlab&gt; to add one.')
            return
        if len(accounts) == 1:
            send(f'🔄 Fetching repos for <b>{html.escape(accounts[0]["username"])}</b>…')
            state._executor.submit(fetch_and_show_repos, uid, 0, 1, None)
            return
        kb = InlineKeyboardMarkup()
        for acc in accounts:
            icon = _GIT_ICONS.get(acc['type'], '🔗')
            label = f'{icon} {acc["username"]} ({acc["type"]})'
            kb.add(InlineKeyboardButton(label, callback_data=f'gh:acc:{acc["idx"]}'))
        send('<b>Select a git account:</b>', reply_markup=kb)

    @state.bot.message_handler(commands=['issues'])
    def cmd_issues(msg: Message):
        if not _authorized(msg): return
        uid = msg.from_user.id
        parts = msg.text.split(maxsplit=1)
        if len(parts) < 2:
            repos = state._registry.list_repos()
            if not repos:
                send('No Repos Tracked Yet. Use /addrepo to add one.')
                return
            kb = InlineKeyboardMarkup()
            for i, p in enumerate(repos):
                kb.add(InlineKeyboardButton(f'🐛 {p.name}', callback_data=f'adm:iss:{i}'))
            send('<b>Select Repo to View Issues:</b>', reply_markup=kb)
            return
        profile = state._registry.get_repo(parts[1].strip())
        if not profile:
            send(f'❌ Repo <code>{html.escape(parts[1].strip())}</code> not found.')
            return
        from nvd_bot.repos.git_providers import make_provider, detect_provider_from_url
        provider_type, base_url = detect_provider_from_url(profile.url)
        acc = state._git_store.find_account_for_host(uid, provider_type, base_url)
        token = acc['token'] if acc else profile.github_token or config.GITHUB_TOKEN
        if not token:
            send('❌ No token for this repo. Connect your account with /connectgit first.')
            return
        owner, repo_name = (profile.name.split('/', 1) if '/' in profile.name
                            else ('', profile.name))
        provider = make_provider(provider_type, base_url)
        send(f'🔄 Fetching issues for <b>{html.escape(profile.name)}</b>…')
        state._executor.submit(fetch_and_show_issues, uid, provider, owner, repo_name, token, 1, None)


def fetch_and_show_repos(uid: int, acc_idx: int, gh_page: int, edit_msg_id):
    from nvd_bot.repos.git_providers import make_provider
    acc = state._git_store.get_account(uid, acc_idx)
    if not acc:
        send(f'❌ Account #{acc_idx} not found.')
        return
    provider = make_provider(acc['type'], acc['base_url'])
    try:
        repos = provider.list_user_repos(acc['token'], page=gh_page, per_page=8)
    except Exception as e:
        send(f'❌ Failed to fetch repos: {html.escape(str(e))}')
        return
    state._user_repo_cache[uid] = {
        'acc_idx': acc_idx,
        'gh_page': gh_page,
        'repos': repos,
        'has_more': len(repos) == 8,
    }
    send_repo_browser(uid, edit_msg_id=edit_msg_id)


def send_repo_browser(uid: int, edit_msg_id=None):
    ctx = state._user_repo_cache.get(uid)
    if not ctx or not ctx['repos']:
        edit_or_send('No repositories found on this page. Try /myrepos to start over.', None, edit_msg_id)
        return

    acc_idx = ctx['acc_idx']
    gh_page = ctx['gh_page']
    repos = ctx['repos']
    has_more = ctx['has_more']

    acc = state._git_store.get_account(uid, acc_idx)
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

    text = (f'{acc_icon} <b>{html.escape(acc_name)}\'s Repositories</b> — page {gh_page}\n\n'
            f'Tap a repo to see options.')
    edit_or_send(text, kb, edit_msg_id)


def send_repo_detail(uid: int, acc_idx: int, ridx: int, repo: dict, edit_msg_id=None):
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
    edit_or_send(text, kb, edit_msg_id, disable_web_page_preview=True)


def fetch_and_show_issues(uid: int, provider, owner: str, repo: str,
                           token: str, gh_page: int, edit_msg_id=None):
    try:
        issues = provider.list_issues(owner, repo, token, page=gh_page, per_page=8)
    except Exception as e:
        send(f'❌ Failed to fetch issues: {html.escape(str(e))}')
        return
    state._user_issue_ctx[uid] = {
        'provider': provider,
        'owner': owner,
        'repo': repo,
        'token': token,
        'issues': issues,
        'gh_page': gh_page,
        'has_more': len(issues) == 8,
    }
    send_issue_list(uid, edit_msg_id)


def send_issue_list(uid: int, edit_msg_id=None):
    ctx = state._user_issue_ctx.get(uid)
    if not ctx:
        edit_or_send('❌ Issue context lost. Please use /issues &lt;repo-id&gt; again.', None, edit_msg_id)
        return

    owner, repo = ctx['owner'], ctx['repo']
    issues = ctx['issues']
    gh_page = ctx['gh_page']
    has_more = ctx['has_more']

    if not issues:
        edit_or_send(
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
    edit_or_send(text, kb, edit_msg_id)


def show_issue_detail(uid: int, provider, owner: str, repo: str,
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
    edit_or_send(text, kb, edit_msg_id, disable_web_page_preview=True)


def _authorized(msg) -> bool:
    from nvd_bot.bot.core import authorized
    return authorized(msg)
