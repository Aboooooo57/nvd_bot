"""Bot initialization, command registration, and authorization."""
from __future__ import annotations

import telebot
from telebot.types import BotCommand

from nvd_bot import config
from nvd_bot.bot import state


def init(registry, gh, llm, git_store=None) -> telebot.TeleBot:
    """Create bot, inject shared state, register all handlers, return bot."""
    state.bot = telebot.TeleBot(config.TELEGRAM_BOT_TOKEN, parse_mode='HTML')
    state._registry = registry
    state._gh = gh
    state._llm = llm
    state._git_store = git_store

    from nvd_bot.bot.handlers import repos
    from nvd_bot.bot.handlers import config as cfg_handlers
    from nvd_bot.bot.handlers import info
    from nvd_bot.bot.handlers import git_connect
    from nvd_bot.bot.handlers import git_browser
    from nvd_bot.bot.callbacks import adm
    from nvd_bot.bot.callbacks import gh as gh_cb

    repos.register()
    cfg_handlers.register()
    info.register()
    git_connect.register()
    git_browser.register()
    adm.register()
    gh_cb.register()

    try:
        state.bot.set_my_commands([
            BotCommand('addrepo',       'Track a repo by URL'),
            BotCommand('removerepo',    'Stop tracking a repo'),
            BotCommand('listrepos',     'List all tracked repos'),
            BotCommand('scanrepo',      'Force re-scan a repo now'),
            BotCommand('repoprofile',   'Show full repo profile JSON'),
            BotCommand('setrepo',       'Set a per-repo config override'),
            BotCommand('connectgit',    'Connect a GitHub or GitLab account'),
            BotCommand('disconnectgit', 'Disconnect a git account'),
            BotCommand('gitaccounts',   'List your connected git accounts'),
            BotCommand('myrepos',       'Browse repos from your git accounts'),
            BotCommand('issues',        'View issues for a tracked repo'),
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

    return state.bot


def authorized(msg) -> bool:
    uid = msg.from_user.id if msg.from_user else None
    if not uid:
        return False
    if config.TELEGRAM_OWNER_ID and uid == config.TELEGRAM_OWNER_ID:
        return True
    return uid in config.get('allowed_user_ids', [])


def is_owner(msg) -> bool:
    uid = msg.from_user.id if msg.from_user else None
    return bool(uid and config.TELEGRAM_OWNER_ID and uid == config.TELEGRAM_OWNER_ID)
