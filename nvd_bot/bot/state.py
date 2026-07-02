"""Shared mutable state for the Telegram bot. All modules import from here."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import telebot

if TYPE_CHECKING:
    from nvd_bot.repos.registry import RepoRegistry
    from nvd_bot.repos.github_client import GithubClient
    from nvd_bot.fixes.llm_client import LLMClient
    from nvd_bot.repos.git_account_store import GitAccountStore

bot: telebot.TeleBot = None
_registry: RepoRegistry = None
_gh: GithubClient = None
_llm: LLMClient = None
_git_store: GitAccountStore = None

_executor = ThreadPoolExecutor(max_workers=4)

# Per-user interaction state (in-memory, non-persistent)
_awaiting_token: dict[int, dict] = {}   # uid → {provider_type, base_url}
_awaiting_url: dict[int, dict] = {}     # uid → {provider_type}
_user_repo_cache: dict[int, dict] = {}  # uid → {acc_idx, gh_page, repos, has_more}
_user_issue_ctx: dict[int, dict] = {}   # uid → {provider, owner, repo, token, gh_page}
