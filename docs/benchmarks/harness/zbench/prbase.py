"""Turning a repository's open pull requests into one buildable ref.

A performance change is only measured against something. With several pull
requests open at once the interesting question is what the repository looks like
with all of them applied, so the numbers for a single branch can be read against
the state it will actually land on.

`--base-ref @merged-prs` does that: it asks the GitHub API which pull requests
are open, merges each head into the base in turn, and hands the resulting commit
to the builder. `--base-ref @main` is the other end of the comparison, and the
two together answer "did this change, or did the branch it sits on".

The merge is done with `git` in a throwaway worktree rather than through the API,
because a merge commit built locally is a thing the builder can actually build,
and one produced by the API would have to be fetched and trusted instead.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from dataclasses import dataclass

#: Sentinel values `--base-ref` accepts in place of a git ref.
MERGED = "@merged-prs"
PLAIN = "@main"


@dataclass
class PullRequest:
    number: int
    title: str
    head: str
    base: str
    url: str
    mergeable: str

    @property
    def short(self) -> str:
        return f"#{self.number} {self.head}"


def _gh(*args: str) -> str:
    """Run `gh` and return stdout, raising with its stderr on failure.

    `gh` rather than a direct API call so the caller's existing authentication is
    what is used, with no token to pass around or to leak into a log.
    """
    proc = subprocess.run(
        ["gh", *args], capture_output=True, text=True, timeout=180
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"gh {' '.join(args[:2])} failed: {(proc.stderr or proc.stdout).strip()[-400:]}"
        )
    return proc.stdout


def list_pull_requests(repo: str, *, state: str = "open") -> list[PullRequest]:
    """Every pull request on `repo`, newest number last.

    Merged and closed ones are excluded by default: a ref built from them would
    be a history, not a state somebody is about to land on.
    """
    raw = _gh(
        "pr", "list", "--repo", repo, "--state", state,
        "--limit", "200", "--json", "number,title,headRefName,baseRefName,url,mergeable",
    )
    items = json.loads(raw)
    return sorted(
        (
            PullRequest(
                number=item["number"],
                title=item.get("title") or "",
                head=item.get("headRefName") or "",
                base=item.get("baseRefName") or "main",
                url=item.get("url") or "",
                mergeable=item.get("mergeable") or "UNKNOWN",
            )
            for item in items
        ),
        key=lambda p: p.number,
    )


def merged_prs_ref(root, repo: str, *, base: str = "main") -> str:
    """A commit with every open pull request on `repo` merged into `base`.

    Returns the commit's sha. Every pull request is fetched by its number rather
    than by head branch name, because a branch that has been deleted still has a
    pull request, and a branch name is not unique across forks.
    """
    pulls = list_pull_requests(repo)
    if not pulls:
        raise SystemExit(
            f"{repo} has no open pull requests to merge, so {MERGED} names no state"
        )
    numbers = " ".join(str(p.number) for p in pulls)
    subprocess.run(
        ["git", "fetch", "--quiet", "origin", base, *(
            f"refs/pull/{n}/head:refs/remotes/prbase/{n}" for n in numbers.split()
        )],
        cwd=root, capture_output=True, text=True, timeout=900, check=True,
    )

    worktree = root.parent / f".zbench-merged-{pulls[0].number}"
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(worktree), f"origin/{base}"],
        cwd=root, capture_output=True, text=True, timeout=300, check=True,
    )
    try:
        head = f"origin/{base}"
        for pull in pulls:
            proc = subprocess.run(
                ["git", "merge", "--no-ff", "--no-edit", f"refs/remotes/prbase/{pull.number}"],
                cwd=worktree, capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0:
                raise SystemExit(
                    f"merging {pull.short} into the combined state failed:\n"
                    f"{(proc.stdout + proc.stderr).strip()[-600:]}"
                )
            head = "HEAD"
            subprocess.run(["git", "add", "-A"], cwd=worktree, capture_output=True)
            if subprocess.run(
                ["git", "commit", "--no-verify", "--allow-empty", "-m",
                 f"merge {pull.short} for the benchmark baseline"],
                cwd=worktree, capture_output=True, timeout=300,
            ).returncode != 0:
                subprocess.run(["git", "add", "-A"], cwd=worktree, capture_output=True)
        merged = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=worktree,
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout.strip()
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=root, capture_output=True, timeout=300,
        )
    return merged


def resolve_base_ref(root, value: str, *, repo: str) -> tuple[str, list[str]]:
    """Turn a `--base-ref` into a commit sha, plus lines describing what it was.

    The description goes into the report, because a number without the state it
    measured against is not evidence.
    """
    if value == MERGED:
        merged = merged_prs_ref(root, repo)
        pulls = list_pull_requests(repo)
        notes = [
            f"every open pull request on `{repo}`, merged into its base "
            f"({len(pulls)} of them): "
            + ", ".join(p.short for p in pulls)
        ]
        return merged, notes
    if value == PLAIN:
        # Resolved by the builder like any other ref, so a run that asks for the
        # base branch gets exactly the commit the remote's default branch names.
        return value, [f"`{value}` -- the repository's default branch, with no pull requests applied"]
    return value, [f"`{value}` -- resolved by the builder as an ordinary git ref"]
