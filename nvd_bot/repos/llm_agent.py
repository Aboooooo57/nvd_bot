from __future__ import annotations
import re
import json

from nvd_bot.repos.profile import RepoProfile
from nvd_bot.repos.github_client import GithubClient

_AGENT_MAX_STEPS = 6
_AGENT_FILE_CAP = 4000   # max chars of a fetched file sent to the model
_AGENT_LIST_CAP = 150    # max file paths shown in the initial prompt

_AGENT_SYSTEM_PROMPT = (
    'You are a dependency-analyzer agent inspecting a source repository to determine the '
    'external packages/libraries it depends on. You may request the contents of files to '
    'investigate (dependency manifests, setup files, imports, docs).\n\n'
    'Respond with EXACTLY ONE JSON object per turn, no extra text, in one of these forms:\n'
    '  {"action": "read_file", "path": "<repo-relative path>"}\n'
    '  {"action": "final", "packages": {"package-name": "version-or-unknown", ...}}\n\n'
    'Inspect likely files (e.g. requirements*.txt, setup.py, pyproject.toml, '
    'environment.yml, package.json, or a few source files for imports) before finalizing. '
    'In the final answer include only real external dependencies — not standard-library '
    'modules and not the project itself. Use "unknown" when you cannot determine a version.'
)


def infer_packages_with_llm(profile: RepoProfile, gh: GithubClient,
                             all_files: list[str], llm,
                             import_hints: dict[str, str] | None = None) -> dict:
    """Agentic dependency inference: the LLM requests files in a loop until it finalizes."""
    from nvd_bot.repos.scanner import _split_name
    owner, repo = _split_name(profile.name)
    file_set = set(all_files)

    file_list = '\n'.join(all_files[:_AGENT_LIST_CAP])
    if len(all_files) > _AGENT_LIST_CAP:
        file_list += f'\n… ({len(all_files) - _AGENT_LIST_CAP} more files not shown)'

    hint_block = ''
    if import_hints:
        hint_block = (
            '\n\nThird-party modules detected in the source imports (names may need '
            'mapping to real package names, versions unknown):\n'
            + ', '.join(sorted(import_hints))
            + '\nUse these as a starting point; confirm names and find versions from '
            'manifest/lock files where possible.'
        )

    messages = [
        {'role': 'system', 'content': _AGENT_SYSTEM_PROMPT},
        {'role': 'user', 'content': (
            f'Repository: {profile.name}\n\n'
            f'Files in repo:\n{file_list}{hint_block}\n\n'
            'Determine the external dependencies. Request files as needed, then finalize.'
        )},
    ]

    read_paths: set[str] = set()
    for step in range(_AGENT_MAX_STEPS):
        response = llm.chat(messages, max_tokens=1000)
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if not json_match:
            print(f'[llm_agent] {profile.name}: step {step}: no JSON in reply, stopping')
            break

        try:
            action = json.loads(json_match.group())
        except Exception:
            print(f'[llm_agent] {profile.name}: step {step}: bad JSON, stopping')
            break

        if action.get('action') == 'final':
            pkgs = {k: str(v) for k, v in (action.get('packages') or {}).items() if k}
            if pkgs:
                print(f'[llm_agent] {profile.name}: inferred {len(pkgs)} packages in {step + 1} step(s)')
                return {'llm-inferred': pkgs}
            return {}

        if action.get('action') == 'read_file':
            path = (action.get('path') or '').strip()
            messages.append({'role': 'assistant', 'content': json_match.group()})
            if path in read_paths:
                feedback = f'(already provided {path}; please request a different file or finalize)'
            elif path not in file_set:
                feedback = f'(file not found: {path}; choose a path from the list or finalize)'
            else:
                read_paths.add(path)
                content = gh.get_file_content(owner, repo, path, token=profile.github_token)
                feedback = (f'Contents of {path}:\n{content[:_AGENT_FILE_CAP]}'
                            if content else f'(file is empty or unreadable: {path})')
            messages.append({'role': 'user', 'content': feedback})
            continue

        print(f'[llm_agent] {profile.name}: step {step}: unknown action, stopping')
        break

    print(f'[llm_agent] {profile.name}: agent did not finalize within {_AGENT_MAX_STEPS} steps')
    return {}
