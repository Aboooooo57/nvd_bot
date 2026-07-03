# NVD Vulnerability Bot

A Telegram bot that monitors the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for new CVEs and alerts you when a vulnerability affects one of your tracked repositories. When a match is found, the bot opens a GitHub issue in the affected repo so you can fix it yourself — the bot never proposes or applies fixes itself, it only tells you where to look.

You can also connect your GitHub and/or GitLab accounts (cloud or self-hosted) and browse, track, and read issues on your repos directly from Telegram.

## How It Works

```
NVD API ──► CVE filter ──► matcher ──► Telegram alert + GitHub issue
                                  ▲
                         repo registry (profile.json per repo)
                                  ▲
                         scanner: manifests → import scan → LLM agent
```

1. Every few minutes the bot fetches recent CVEs from NVD.
2. CVEs are filtered by your watchlist keywords and severity threshold.
3. Each CVE's affected packages are matched against the dependency lists of your tracked repos.
4. On a match, a Telegram alert is sent and a GitHub issue is opened in the affected repo.

Dependency discovery runs in three layers so repos with non-standard structures still get covered:

1. **Manifest parsers** — parse standard dependency files deterministically (no LLM needed).
2. **Source import scan** — reads `.py` files and infers packages from `import` statements.
3. **Agentic LLM loop** — multi-turn conversation where the LLM requests files, receives their content, and finalizes the package list.

## Prerequisites

- Docker and Docker Compose
- Telegram bot token — create one with [@BotFather](https://t.me/BotFather)
- Your Telegram user ID (get it from [@userinfobot](https://t.me/userinfobot)) — set as `TELEGRAM_OWNER_ID`
- Target chat/group ID — set as `CHAT_ID`
- GitHub personal access token with `repo` scope
- NVD API key (optional but recommended — [request one here](https://nvd.nist.gov/developers/request-an-api-key))
- LLM access — one of: OpenRouter (hosted), a self-hosted LiteLLM proxy, or a Google Gemini API key (direct, no proxy)

## Setup

### 1. Clone and configure

```bash
git clone https://github.com/aboooooo57/nvd_bot.git
cd nvd_bot
cp .env.example .env
```

Edit `.env` and fill in your values (see the table below).

### 2. Start the bot

```bash
docker compose up -d
docker compose logs -f
```

## Environment Variables

Create a `.env` file in the project root. All secrets belong here — never commit them.

```env
# Telegram
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
CHAT_ID=-1001234567890
TELEGRAM_OWNER_ID=123456789

# NVD (optional — higher rate limits)
NVD_API_KEY=your-nvd-api-key

# GitHub (required for scanning repos and opening issues)
GITHUB_TOKEN=ghp_...

# LLM — pick ONE option:

# Option A: OpenRouter (hosted, 200+ models)
OPENROUTER_API_KEY=sk-or-...

# Option B: Self-hosted LiteLLM proxy
LITELLM_BASE_URL=https://your-litellm-proxy.example.com
LITELLM_API_KEY=your-proxy-key

# Option C: Google Gemini (direct API, no proxy needed)
GEMINI_API_KEY=your-gemini-api-key

# Optional: GitHub OAuth App — enables /connectgit Device Flow for github.com
# (leave blank to fall back to PAT paste flow, which works for all providers)
GITHUB_OAUTH_CLIENT_ID=
GITHUB_OAUTH_CLIENT_SECRET=
```

| Variable | Required | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | yes | Bot token from BotFather |
| `CHAT_ID` | yes | Target group, channel, or DM ID |
| `TELEGRAM_OWNER_ID` | yes | Your Telegram user ID (owner-only commands) |
| `NVD_API_KEY` | recommended | NVD API key for higher rate limits |
| `GITHUB_TOKEN` | yes | PAT with `repo` scope |
| `OPENROUTER_API_KEY` | option A | OpenRouter API key |
| `LITELLM_BASE_URL` | option B | Self-hosted LiteLLM proxy URL |
| `LITELLM_API_KEY` | option B | Proxy authentication key |
| `GEMINI_API_KEY` | option C | Google Gemini API key ([get one here](https://aistudio.google.com/apikey)) |
| `GITHUB_OAUTH_CLIENT_ID` | optional | GitHub OAuth App client ID, enables Device Flow in `/connectgit` |
| `GITHUB_OAUTH_CLIENT_SECRET` | optional | GitHub OAuth App client secret |

**LLM auto-detection:** provider is chosen by which keys are set, in this order — `OPENROUTER_API_KEY` first, then `LITELLM_BASE_URL`/`LITELLM_API_KEY` (→ `litellm_proxy`), then `GEMINI_API_KEY` (→ direct Gemini). Set exactly one option's keys and the bot picks it up automatically — no separate provider flag needed.

## Bot Commands

| Command | Description |
|---|---|
| `/addrepo <github-url> [token]` | Track a repo and scan its dependencies |
| `/removerepo <id>` | Stop tracking a repo |
| `/listrepos` | List all tracked repos with status |
| `/scanrepo <id>` | Force re-scan a repo now |
| `/repoprofile <id>` | Show the full repo profile JSON |
| `/setrepo <id> <key> <value>` | Override a per-repo config setting |
| `/connectgit [type] [base_url]` | Connect a GitHub or GitLab account (OAuth Device Flow or PAT) |
| `/disconnectgit [index]` | Disconnect a connected git account |
| `/gitaccounts` | List your connected git accounts |
| `/myrepos` | Browse repos from your connected accounts and track them by tapping |
| `/issues <repo-id>` | Browse open issues for a tracked repo |
| `/settings` | Show all current settings |
| `/setconfig <key> <value>` | Update a config value live |
| `/addkeyword <word>` | Add a CVE watchlist keyword |
| `/removekeyword <word>` | Remove a watchlist keyword |
| `/llmcheck [model]` | Test the LLM connection and measure latency |
| `/status` | System status overview |
| `/adduser <telegram-id>` | Grant bot access to a user (owner only) |
| `/removeuser <telegram-id>` | Revoke bot access from a user (owner only) |
| `/help` | Show all commands |

The bot is **issue-only**: it never opens pull requests or applies fixes itself. On a CVE match it opens a GitHub issue with the affected package, installed version, and vulnerable range, and leaves the fix to you.

## Dependency Scanning

### Layer 1 — Manifest parsers (deterministic)

The scanner looks for these files anywhere in the repo tree (suffix-matched, so `setup/environment.yml` is found too):

- Python: `requirements.txt`, `requirements-dev.txt`, `requirements.in`, `requirements/base.txt`, `requirements/prod.txt`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Pipfile`
- Conda: `environment.yml`, `environment-linux.yml` (top-level deps + nested `pip:` block)
- Node: `package.json`
- Go: `go.mod`
- Ruby: `Gemfile`

### Layer 2 — Source import scan

If no manifest is found, the bot reads up to 50 `.py` files, extracts `import` statements, filters out the standard library and local modules, and maps import names to PyPI package names (e.g. `yaml` → `pyyaml`, `cv2` → `opencv-python`, `bs4` → `beautifulsoup4`). Results are marked `(import-scan)` in scan output.

### Layer 3 — Agentic LLM loop

If import scanning is inconclusive, the bot runs a multi-turn conversation with the LLM (up to 6 steps). The LLM may request specific files using:

```json
{"action": "read_file", "path": "path/to/file"}
```

The bot fetches the file and sends the content back. The LLM finalizes with:

```json
{"action": "final", "packages": {"requests": "2.31.0", "flask": "unknown"}}
```

Results are marked `(LLM-inferred — verify manually)` in scan output.

## Configuration Reference

Settings are stored in `data/config.json` (git-ignored — it's per-deployment runtime state, not source) and can be changed live with `/setconfig <key> <value>`.

| Key | Default | Description |
|---|---|---|
| `nvd_poll_interval_minutes` | `5` | How often to check NVD for new CVEs |
| `cve_lookback_minutes` | `6` | Look-back window for new CVEs |
| `commit_poll_interval_minutes` | `15` | How often to check tracked repos for new commits |
| `severity_threshold` | `MEDIUM` | Minimum CVE severity to open a GitHub issue (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) |
| `seen_cve_limit` | `1000` | Max CVE IDs to remember (deduplication) |
| `watchlist` | `[python, node, linux, ...]` | Keywords matched against CVE descriptions |
| `daily_summary_time` | `23:55` | Time for daily summary message (HH:MM) |
| `llm_provider` | `openrouter` | `openrouter`, `litellm_proxy`, or `gemini` (usually auto-detected — see above) |
| `llm_model` | `gemini-3.5-flash` | Model identifier — must match a model your active provider actually serves |
| `llm_max_tokens` | `2000` | Max tokens per LLM response |
| `allowed_user_ids` | `[]` | Telegram user IDs with bot access |

CVEs below `severity_threshold` are never filtered out of Telegram alerts or the daily digest — the threshold only gates whether a GitHub issue gets opened, so you're not woken up for a `LOW` severity bug in a dev dependency while still seeing it in the feed.

Example: raise the severity threshold so only high-severity CVEs create issues:

```
/setconfig severity_threshold HIGH
```

## LLM Provider Notes

**OpenRouter (option A):** Set `OPENROUTER_API_KEY`. Model names use the format `openrouter/provider/model`, e.g. `openrouter/anthropic/claude-3-haiku`. Test with `/llmcheck`.

**LiteLLM proxy (option B):** Set `LITELLM_BASE_URL` and `LITELLM_API_KEY`. The bot calls the proxy with a plain HTTP `POST` (not the openai SDK) to avoid WAF rejection from SDK-specific headers. The model name is sent verbatim, so set it without any provider prefix, e.g. `gemini/gemini-3.5-flash`. Test with `/llmcheck`.

**Google Gemini, direct (option C):** Set `GEMINI_API_KEY` — no proxy or gateway needed. Set `llm_model` to a real Gemini model id via `/setconfig llm_model gemini-2.0-flash` (the `gemini-3.5-flash` default is a proxy-specific alias, not a real Google model name — update it once you switch to direct Gemini). The bot prefixes the model with `gemini/` automatically when calling the API. Test with `/llmcheck`.

## Per-Repo Profile

When a repo is added or scanned, the bot commits `.nvd_bot/profile.json` to **the target repo** (not this one). This file stores the detected package list, primary language, last scan timestamp, and any per-repo config overrides. It is updated automatically on every scan.

## Security Notes

- Unauthorized users get no response — the bot ignores them silently
- Secrets (tokens, API keys) belong only in `.env`; never commit them
- Per-user Git OAuth tokens/PATs from `/connectgit` are stored in `data/user_git_accounts.json`, never in `config.json` — this file is git-ignored and should never be committed
- `data/config.json` is runtime, per-deployment state (git-ignored) — it is not shared or synced between deployments
- The `data/` directory is mounted as a Docker volume and persists across restarts
- Per-repo `.nvd_bot/profile.json` is committed to **the tracked target repo**, never to this bot's own repo

## Project Layout

```
nvd_bot/
├── nvd_bot/
│   ├── main.py               # CVE pipeline, severity gating, GitHub issue creation
│   ├── config.py             # Settings loader (env vars + config.json)
│   ├── scheduler.py          # Poll timers
│   ├── bot/                  # Telegram bot package
│   │   ├── core.py           # Bot init, command registration, authorization
│   │   ├── state.py          # Shared in-memory state (bot instance, caches)
│   │   ├── utils.py          # Shared send/format helpers
│   │   ├── handlers/         # One file per command group (repos, config, info,
│   │   │                     #   git_connect, git_browser)
│   │   └── callbacks/        # Inline-keyboard callback handlers
│   ├── nvd/                  # NVD API client, CVE filter, formatter
│   ├── repos/                # Repo registry, profile model, GitHub/GitLab clients
│   │   ├── scanner.py        # Orchestrator: manifest → import scan → LLM agent
│   │   ├── dep_parser.py     # Manifest file parsers (Layer 1)
│   │   ├── import_scanner.py # Source import scan (Layer 2)
│   │   ├── llm_agent.py      # Agentic LLM inference loop (Layer 3)
│   │   ├── git_providers.py  # GitHub/GitLab API abstraction
│   │   ├── git_account_store.py # Per-user connected git accounts
│   │   └── device_flow.py    # GitHub OAuth Device Flow
│   ├── matching/              # CVE-to-repo matcher
│   └── fixes/                 # LLM client (OpenRouter / LiteLLM proxy / Gemini)
├── data/                      # Runtime data (volume-mounted, git-ignored)
│   ├── config.json            # Live settings
│   ├── seen_cves.csv          # Deduplication store
│   ├── user_git_accounts.json # Per-user OAuth tokens/PATs
│   └── repos/                 # Repo registry and cached profiles
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```
