from __future__ import annotations
from datetime import datetime, timezone

from nvd_bot import config
from nvd_bot.repos.profile import RepoProfile
from nvd_bot.repos.github_client import GithubClient
from nvd_bot.repos.dep_parser import _DEP_FILES, parse_file, detect_language
from nvd_bot.repos.import_scanner import scan_source_imports
from nvd_bot.repos.llm_agent import infer_packages_with_llm


def scan_repo(profile: RepoProfile, gh: GithubClient, llm=None) -> dict:
    """
    Fetch dependency files from the repo, update the profile, and push
    .nvd_bot/profile.json back. Falls back to LLM inference if no manifest found.
    Returns the updated packages dict.
    """
    owner, repo = _split_name(profile.name)
    if not owner:
        print(f'[scanner] Cannot parse repo name: {profile.name}')
        return profile.packages

    all_files = gh.list_files(owner, repo, token=profile.github_token)
    packages: dict[str, dict[str, str]] = {}

    for dep_file in _DEP_FILES:
        matched_paths = [f for f in all_files if f == dep_file or f.endswith('/' + dep_file)]
        for matched_path in matched_paths:
            content = gh.get_file_content(owner, repo, matched_path, token=profile.github_token)
            if not content:
                continue
            parsed = parse_file(dep_file, content)
            if parsed:
                packages[matched_path] = parsed
                print(f'[scanner] {profile.name}: parsed {matched_path} ({len(parsed)} packages)')

    profile._llm_scan_error = None  # transient; not serialised by to_dict()
    if not packages:
        print(f'[scanner] {profile.name}: no dep files found, scanning source imports…')
        import_pkgs = scan_source_imports(profile, gh, all_files)
        if import_pkgs:
            print(f'[scanner] {profile.name}: import scan found {len(import_pkgs)} modules')
        if llm:
            try:
                inferred = infer_packages_with_llm(profile, gh, all_files, llm,
                                                   import_hints=import_pkgs)
                if inferred:
                    packages = inferred
            except Exception as e:
                profile._llm_scan_error = str(e)
                print(f'[scanner] {profile.name}: LLM inference failed: {e}')
        if not packages and import_pkgs:
            packages = {'import-scan': import_pkgs}

    language, frameworks = detect_language(all_files, packages)

    profile.packages = packages
    profile.language = language
    profile.frameworks = frameworks
    profile.last_scanned_at = datetime.now(timezone.utc).isoformat()

    _push_profile(profile, gh, owner, repo)
    return packages


def _push_profile(profile: RepoProfile, gh: GithubClient, owner: str, repo: str):
    """Commit .nvd_bot/profile.json into the tracked repo."""
    import json
    profile_path = config.get('profile_file_path', '.nvd_bot/profile.json')
    safe = profile.to_dict()
    safe.pop('github_token', None)
    content = json.dumps(safe, indent=2)
    default_branch = gh.get_default_branch(owner, repo, token=profile.github_token)
    ok = gh.commit_file(
        owner, repo, profile_path, content,
        message='chore: update nvd_bot profile [skip ci]',
        branch=default_branch,
        token=profile.github_token,
    )
    if ok:
        print(f'[scanner] Pushed profile to {profile.name}:{profile_path}')
    else:
        print(f'[scanner] Failed to push profile to {profile.name}')


def _split_name(name: str) -> tuple[str, str]:
    parts = name.rstrip('/').split('/')
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return '', ''
