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
    if not all_files:
        # list_files() already logged the failure. Bailing out here (instead
        # of falling through to the import-scan/LLM fallback) matters
        # specifically when this repo previously had real manifest-parsed
        # packages: a transient GitHub API hiccup must not silently replace
        # a good profile with an empty one and push that over the good copy.
        profile._scan_skipped = 'could not list repo files — kept previous data'
        print(f'[scanner] {profile.name}: {profile._scan_skipped}')
        return profile.packages

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

    if not packages and profile.packages:
        # A rescan that found nothing at all — no manifests, no source
        # imports, and the LLM fallback found nothing usable either — while
        # the existing profile already had real data is far more likely a
        # partial failure (truncated file listing on a large repo tree,
        # exhausted LLM fallback, an API hiccup between calls) than the repo
        # having genuinely dropped every dependency. Refuse to overwrite:
        # leave profile.packages/language/frameworks untouched and don't
        # push, so the caller's registry update just re-persists the
        # profile unchanged instead of replacing good data with nothing.
        had = sum(len(p) for p in profile.packages.values())
        profile._scan_skipped = (
            'scan found 0 packages — kept previous data '
            f'({had} package(s)) instead of overwriting it'
        )
        print(f'[scanner] {profile.name}: {profile._scan_skipped}')
        return profile.packages

    profile._scan_skipped = None
    language, frameworks = detect_language(all_files, packages)

    profile.packages = packages
    profile.language = language
    profile.frameworks = frameworks
    profile.last_scanned_at = datetime.now(timezone.utc).isoformat()

    _push_profile(profile, gh, owner, repo)
    return packages


def restore_from_committed_profile(profile: RepoProfile, gh: GithubClient) -> tuple[bool, str]:
    """Recover packages/language/frameworks from the .nvd_bot/profile.json
    already committed in the tracked repo, instead of a full re-scan.

    Every successful scan pushes this file into the target repo, so it
    doubles as a backup of the last good result — useful when the bot's
    own local copy gets mistakenly cleared (a failed scan from before the
    empty-result guards existed, a bad manual edit, registry corruption)
    but the repo's committed copy is still intact.

    Returns (restored, message). Never touches the profile if there's
    nothing usable to restore.
    """
    import json
    owner, repo = _split_name(profile.name)
    if not owner:
        return False, f'cannot parse repo name: {profile.name}'

    profile_path = config.get('profile_file_path', '.nvd_bot/profile.json')
    content = gh.get_file_content(owner, repo, profile_path, token=profile.github_token)
    if not content:
        return False, f'no {profile_path} found in the repo — nothing to restore, try /scanrepo instead'

    try:
        remote = json.loads(content)
    except Exception as e:
        return False, f'could not parse {profile_path}: {e}'

    remote_packages = remote.get('packages') or {}
    remote_count = sum(len(p) for p in remote_packages.values())
    if remote_count == 0:
        return False, (f'{profile_path} in the repo has no packages either — '
                        f'nothing to restore, try /scanrepo instead')

    profile.packages = remote_packages
    profile.language = remote.get('language', profile.language)
    profile.frameworks = remote.get('frameworks', profile.frameworks)
    profile.last_scanned_at = remote.get('last_scanned_at', profile.last_scanned_at)
    profile._scan_skipped = None
    return True, f'restored {remote_count} package(s) from {profile_path}'


def _push_profile(profile: RepoProfile, gh: GithubClient, owner: str, repo: str):
    """Commit .nvd_bot/profile.json into the tracked repo.

    Sets profile.last_commit_sha to the sha of the commit this push just
    created, so the next commit-poll cycle recognizes it as already-seen
    instead of mistaking the bot's own profile update for a new upstream
    commit and re-scanning/re-pushing forever.
    """
    import json
    profile_path = config.get('profile_file_path', '.nvd_bot/profile.json')
    safe = profile.to_dict()
    safe.pop('github_token', None)
    content = json.dumps(safe, indent=2)
    default_branch = gh.get_default_branch(owner, repo, token=profile.github_token)
    new_sha = gh.commit_file(
        owner, repo, profile_path, content,
        message='chore: update nvd_bot profile [skip ci]',
        branch=default_branch,
        token=profile.github_token,
    )
    if new_sha:
        profile.last_commit_sha = new_sha
        print(f'[scanner] Pushed profile to {profile.name}:{profile_path}')
    else:
        print(f'[scanner] Failed to push profile to {profile.name}')


def _split_name(name: str) -> tuple[str, str]:
    parts = name.rstrip('/').split('/')
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return '', ''
