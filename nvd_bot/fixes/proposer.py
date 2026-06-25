from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

from nvd_bot.matching.matcher import MatchResult
from nvd_bot.repos.github_client import GithubClient
from nvd_bot.fixes.llm_client import LLMClient
from nvd_bot.fixes.pending import PendingFix, _short_id
from nvd_bot.nvd.formatter import extract_meta
from nvd_bot.repos.scanner import _split_name


_SYSTEM_PROMPT = """You are a security engineer. Your task is to generate minimal, safe dependency fixes for security vulnerabilities.

Given a CVE description, the vulnerable package(s), and the current dependency file content, output ONLY a JSON object with these exact keys:
- fixed_file_content: the complete updated file content (string)
- explanation: one paragraph describing what was changed and why (string)
- fix_type: either "version_bump" or "code_patch" (string)

Rules:
- Make the minimal change needed to resolve the vulnerability
- Prefer bumping to the lowest safe version, not the latest
- Do not change unrelated dependencies
- Preserve all comments, formatting, and structure of the original file
- Return ONLY the JSON object, no markdown, no extra text"""


@dataclass
class FixProposal:
    file_path: str
    original_content: str
    fixed_content: str
    explanation: str
    fix_type: str


def generate_fix(
    match: MatchResult,
    cve_item: dict,
    gh: GithubClient,
    llm: LLMClient,
) -> Optional[PendingFix]:
    cve_id, description, severity, _ = extract_meta(cve_item)
    owner, repo = _split_name(match.repo.name)
    if not owner:
        return None

    # Use the first matched package's source file
    if not match.matched_packages:
        return None
    first_pkg = match.matched_packages[0]
    source_file = match.source_files.get(first_pkg, 'requirements.txt')

    # Fetch current file content from GitHub
    original_content = gh.get_file_content(owner, repo, source_file,
                                             token=match.repo.github_token)
    if not original_content:
        print(f'[proposer] Could not fetch {source_file} from {match.repo.name}')
        return None

    user_prompt = _build_prompt(
        cve_id=cve_id,
        description=description,
        matched_packages=match.matched_packages,
        current_versions=match.current_versions,
        affected_specs=match.affected_specs,
        file_name=source_file,
        file_content=original_content,
        language=match.repo.language,
    )

    try:
        raw = llm.generate(_SYSTEM_PROMPT, user_prompt)
    except Exception as e:
        print(f'[proposer] LLM call failed: {e}')
        return None

    parsed = _parse_response(raw)
    if not parsed:
        print(f'[proposer] Could not parse LLM response for {cve_id}')
        return None

    fixed_content, explanation, fix_type = parsed

    return PendingFix(
        fix_id=_short_id(),
        cve_id=cve_id,
        repo_id=match.repo.id,
        repo_name=match.repo.name,
        file_path=source_file,
        original_content=original_content,
        fixed_content=fixed_content,
        explanation=explanation,
        fix_type=fix_type,
        status='pending',
        created_at=datetime.now(timezone.utc).isoformat(),
        severity=severity,
    )


def _build_prompt(cve_id: str, description: str, matched_packages: list[str],
                   current_versions: dict, affected_specs: dict,
                   file_name: str, file_content: str, language: str) -> str:
    pkg_lines = []
    for pkg in matched_packages:
        ver = current_versions.get(pkg, 'unknown')
        specs = affected_specs.get(pkg, [])
        spec_str = ', '.join(specs) if specs else 'unknown range'
        pkg_lines.append(f'  - {pkg}: current={ver}, vulnerable range: {spec_str}')
    pkg_summary = '\n'.join(pkg_lines)

    return f"""CVE ID: {cve_id}
Language: {language}
Description: {description[:600]}

Vulnerable packages found in this repo:
{pkg_summary}

File to fix: {file_name}
Current content:
```
{file_content[:4000]}
```

Generate the fix JSON."""


def _parse_response(raw: str) -> Optional[tuple[str, str, str]]:
    # Strip markdown code fences if present
    text = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
    text = re.sub(r'\s*```$', '', text.strip(), flags=re.MULTILINE)
    try:
        data = json.loads(text.strip())
        return (
            data['fixed_file_content'],
            data['explanation'],
            data.get('fix_type', 'version_bump'),
        )
    except Exception:
        pass
    # Regex fallback: try to extract a version bump directly
    m = re.search(r'"fixed_file_content"\s*:\s*"(.*?)"(?:,|\})', raw, re.DOTALL)
    e = re.search(r'"explanation"\s*:\s*"(.*?)"(?:,|\})', raw, re.DOTALL)
    if m and e:
        return m.group(1).replace('\\n', '\n'), e.group(1), 'version_bump'
    return None
