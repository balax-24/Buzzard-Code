"""
Git workflow tools for Buzzard Code: branches, commits and pull-request drafts.

- git_prepare_commit (read-only): what would be committed, the repository's recent message
  style, and warnings about files that should not be committed.
- git_branch_create (asks for approval): creates and switches to a new branch.
- git_commit (asks for approval): stages the named paths and commits with the given message.
- git_prepare_pr (read-only): the commits and diff summary for a pull request, plus a drafted
  title and body.

Guarantees:
- Nothing here pushes, force-updates, rewrites history, or contacts a remote. git_prepare_pr
  returns the push and PR commands for the user to run themselves.
- Commits never skip hooks (no --no-verify) and refuse files that look like secrets.
- Every path is checked against the workspace boundary; arguments go to git as an argument
  list, never through a shell.
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import List, Optional, Tuple

from tools.filesystem import get_active_workspace, get_safe_path
from tools.git_tools import _run_git_cmd

MAX_SUBJECT_CHARS = 72
SENSITIVE_FILE_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_rsa*", "id_ed25519*",
    "*.keystore", "*.jks", "credentials", "credentials.json", "*secret*", ".npmrc", ".pypirc",
)
SAFE_SENSITIVE_EXCEPTIONS = (".env.example", ".env.sample", ".env.template")


def _not_a_repo(err: str) -> Optional[str]:
    if "not a git repository" in err.lower():
        return f"Error: Workspace '{get_active_workspace()}' is not a git repository."
    return None


def _is_sensitive(path: str) -> bool:
    name = os.path.basename(path.replace("\\", "/"))
    if name in SAFE_SENSITIVE_EXCEPTIONS:
        return False
    return any(fnmatch.fnmatch(name.lower(), pattern) for pattern in SENSITIVE_FILE_PATTERNS)


def _changed_files() -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """Returns (error, [(status, path)]) for staged, unstaged and untracked changes."""
    ret, out, err = _run_git_cmd(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if ret != 0:
        return (_not_a_repo(err) or f"Error running git status: {err.strip()}"), []
    entries: List[Tuple[str, str]] = []
    parts = out.split("\0")
    index = 0
    while index < len(parts):
        item = parts[index]
        index += 1
        if len(item) < 4:
            continue
        status, path = item[:2], item[3:]
        if status[0] in "RC":
            index += 1  # skip the rename source
        entries.append((status, path))
    return None, entries


def _current_branch() -> str:
    ret, out, _err = _run_git_cmd(["rev-parse", "--abbrev-ref", "HEAD"])
    return out.strip() if ret == 0 else ""


def git_prepare_commit() -> str:
    """
    Shows what a commit would contain, recent commit messages for style, and files that
    should not be committed. Read-only.
    """
    error, entries = _changed_files()
    if error:
        return error
    if not entries:
        return "Nothing to commit: the working tree is clean."
    staged = [p for s, p in entries if s[0] not in " ?"]
    unstaged = [p for s, p in entries if s[1] != " " and s != "??"]
    untracked = [p for s, p in entries if s == "??"]
    sensitive = sorted({p for _s, p in entries if _is_sensitive(p)})
    _ret, stat, _err = _run_git_cmd(["diff", "HEAD", "--stat"])
    _ret, log, _err = _run_git_cmd(["log", "-n8", "--format=%s"])
    sections = [f"Branch: {_current_branch() or 'unknown'}"]
    for title, items in (("Staged", staged), ("Modified, not staged", unstaged), ("Untracked", untracked)):
        if items:
            sections.append(f"{title} ({len(items)}): " + ", ".join(items[:40]))
    if stat.strip():
        sections.append("Diff summary:\n" + stat.strip())
    if log.strip():
        sections.append("Recent commit messages (match this style):\n" + log.strip())
    if sensitive:
        sections.append("Do not commit (look like secrets): " + ", ".join(sensitive))
    sections.append(
        "To commit, call git_commit with the paths to include and a message whose first line is "
        f"at most {MAX_SUBJECT_CHARS} characters. The user approves the commit."
    )
    return "\n\n".join(sections)


_BRANCH_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


def git_branch_create(name: str, base: str = "") -> str:
    """
    Creates a new branch and switches to it. Uncommitted changes come along. Needs approval.
    Arguments:
        name: New branch name, e.g. 'fix/discount-rounding'.
        base: Optional branch or commit to start from (default: the current commit).
    """
    name = str(name or "").strip()
    base = str(base or "").strip()
    if not _BRANCH_NAME.match(name) or ".." in name or name.endswith((".lock", "/", ".")):
        return "Error: branch names may use letters, digits, '.', '_', '-' and '/', and must start with a letter or digit."
    ret, _out, err = _run_git_cmd(["check-ref-format", "--branch", name])
    if ret != 0:
        return _not_a_repo(err) or f"Error: '{name}' is not a valid branch name."
    if base and (base.startswith("-") or not _BRANCH_NAME.match(base)):
        return "Error: base must be a branch name or commit id."
    ret, _out, _err = _run_git_cmd(["rev-parse", "--verify", "--quiet", f"refs/heads/{name}"])
    if ret == 0:
        return f"Error: branch '{name}' already exists. Pick another name."
    args = ["switch", "-c", name] + ([base] if base else [])
    ret, out, err = _run_git_cmd(args)
    if ret != 0:
        return _not_a_repo(err) or f"Error creating branch: {(err or out).strip()}"
    return f"Created and switched to branch '{name}'" + (f" from '{base}'." if base else ".")


def _validate_message(message: str) -> Optional[str]:
    message = str(message or "").strip()
    if not message:
        return "Error: the commit message is empty."
    subject = message.splitlines()[0].strip()
    if not subject:
        return "Error: the first line of the commit message is empty."
    if len(subject) > MAX_SUBJECT_CHARS:
        return f"Error: the first line is {len(subject)} characters; keep it to {MAX_SUBJECT_CHARS} and put detail in the body."
    return None


def git_commit(message: str, paths: str = "") -> str:
    """
    Stages the given paths and commits them. Runs the repository's commit hooks. Needs approval.
    Arguments:
        message: Commit message; first line at most 72 characters, optional body after a blank line.
        paths: Files or folders to include, separated by spaces or newlines. Empty commits
               only what is already staged.
    """
    problem = _validate_message(message)
    if problem:
        return problem
    requested = [p for p in re.split(r"[\s,]+", str(paths or "").strip()) if p]
    relative: List[str] = []
    for path in requested:
        if path.startswith("-"):
            return f"Error: '{path}' is not a path."
        try:
            safe = get_safe_path(path)
        except PermissionError as error:
            return f"Error: {error}"
        rel = os.path.relpath(safe, get_active_workspace()).replace("\\", "/")
        if rel == "." or not os.path.exists(safe):
            ret, _o, _e = _run_git_cmd(["ls-files", "--deleted", "--error-unmatch", "--", rel])
            if rel == "." or ret != 0:
                return f"Error: '{path}' does not exist; name the specific files to commit."
        relative.append(rel)

    error, entries = _changed_files()
    if error:
        return error
    if relative:
        candidates = [p for _s, p in entries if any(p == r or p.startswith(r.rstrip("/") + "/") for r in relative)]
    else:
        candidates = [p for s, p in entries if s[0] not in " ?"]
    sensitive = sorted({p for p in candidates if _is_sensitive(p)})
    if sensitive:
        return "Error: refusing to commit files that look like secrets: " + ", ".join(sensitive) + ". Leave them out or add them to .gitignore."
    if not candidates:
        return "Error: nothing to commit for those paths." if relative else "Error: nothing is staged; name the paths to commit."

    if relative:
        ret, out, err = _run_git_cmd(["add", "--"] + relative)
        if ret != 0:
            return _not_a_repo(err) or f"Error staging files: {(err or out).strip()}"
    ret, out, err = _run_git_cmd(["commit", "-m", str(message).strip()], timeout=120)
    if ret != 0:
        detail = (err or out).strip()
        if "hook" in detail.lower():
            return f"Commit stopped by a repository hook. Fix the problem it reports, then commit again:\n{detail}"
        return f"Error committing: {detail}"
    _r, head, _e = _run_git_cmd(["log", "-n1", "--format=%h %s"])
    return f"Committed {head.strip()} on '{_current_branch()}'. Nothing was pushed."


def git_prepare_pr(base: str = "main") -> str:
    """
    Drafts a pull request for the current branch against base: commits, changed files and a
    suggested title and body. Read-only; does not push or open the PR.
    Arguments:
        base: Branch the PR will merge into (default 'main').
    """
    base = str(base or "main").strip()
    if base.startswith("-") or not _BRANCH_NAME.match(base):
        return "Error: base must be a branch name."
    ret, out, err = _run_git_cmd(["rev-parse", "--abbrev-ref", "HEAD"])
    if ret != 0:
        return _not_a_repo(err) or f"Error: could not read the current branch: {(err or out).strip()}"
    branch = out.strip()
    if branch in ("HEAD", base):
        return f"Error: you are on '{branch}'. Create a feature branch with git_branch_create first."
    ret, merge_base, err = _run_git_cmd(["merge-base", base, "HEAD"])
    if ret != 0:
        return f"Error: could not compare with '{base}': {(err or merge_base).strip() or 'branch not found'}."
    merge_base = merge_base.strip()
    _r, commits, _e = _run_git_cmd(["log", "--format=- %s", f"{merge_base}..HEAD"])
    if not commits.strip():
        return f"Error: '{branch}' has no commits that are not already on '{base}'."
    _r, stat, _e = _run_git_cmd(["diff", "--stat", f"{merge_base}..HEAD"])
    error, entries = _changed_files()
    subjects = [line[2:] for line in commits.strip().splitlines()]
    title = subjects[-1]  # git log lists newest first, so this is the first commit
    dirty = "\nNote: there are uncommitted changes that this PR would not include." if entries and not error else ""
    return (
        f"Branch '{branch}' -> '{base}', {len(subjects)} commit(s).{dirty}\n\n"
        f"Suggested title: {title}\n\n"
        "Suggested body:\n"
        "## Summary\n" + commits.strip() + "\n\n"
        "## Changes\n" + (stat.strip() or "(no file changes)") + "\n\n"
        "## Testing\n(describe the tests run and their results)\n\n"
        "Nothing has been pushed. When the user is ready, they run:\n"
        f"  git push -u origin {branch}\n"
        f"  gh pr create --base {base} --title \"<title>\" --body-file <file>"
    )


def register_git_workflow_tools(registry) -> None:
    from tools.registry import ToolCategory

    read_only = dict(category=ToolCategory.AUTOMATION, risk_level="LOW", read_only=True,
                     sandbox_required=False, scope_required=False, approval_required=False, timeout=30)
    writes = dict(category=ToolCategory.AUTOMATION, risk_level="MEDIUM", read_only=False, destructive=False,
                  sandbox_required=False, scope_required=False, approval_required=True, timeout=120)
    registry.register(
        name="git_prepare_commit",
        description="Shows staged, modified and untracked files, a diff summary, recent commit messages for style, and files that must not be committed. No arguments.",
        func=git_prepare_commit, **read_only,
    )
    registry.register(
        name="git_branch_create",
        description="Creates a new branch and switches to it (the user approves). Arguments: name (str), base (str, optional).",
        func=git_branch_create, **writes,
    )
    registry.register(
        name="git_commit",
        description="Stages the named paths and commits them with hooks enabled (the user approves). Never pushes. Arguments: message (str), paths (str, space-separated; empty commits what is staged).",
        func=git_commit, **writes,
    )
    registry.register(
        name="git_prepare_pr",
        description="Drafts a pull request title and body for the current branch against base. Does not push or open the PR. Arguments: base (str, default 'main').",
        func=git_prepare_pr, **read_only,
    )
