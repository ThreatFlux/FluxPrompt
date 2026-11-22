"""Require untagged versions to originate in a signed automation release PR."""

import json
import os
import re
import subprocess
import sys
import tomllib


def git(*args):
    return subprocess.check_output(("git", *args), text=True, encoding="utf-8").strip()


def api(repo, path):
    return json.loads(
        subprocess.check_output(
            ("gh", "api", "--paginate", "--slurp", f"repos/{repo}/{path}"),
            encoding="utf-8",
        )
    )


def manifest_version(sha):
    return tomllib.loads(git("show", f"{sha}:Cargo.toml"))["package"]["version"]


def version_origin(candidate, version):
    # Follow main's first parents so a proposal's side-branch commit cannot
    # stand in for the commit that actually integrated the version.
    history = git(
        "log", "--first-parent", "--full-history", "--format=%H", candidate,
        "--", "Cargo.toml",
    ).splitlines()
    origin = None
    for sha in history:
        if manifest_version(sha) != version:
            break
        origin = sha
    if origin is None:
        raise ValueError("Cannot locate the version's origin on main")
    return origin


def proposal_head(pulls, repo, author, origin, tag):
    matches = [
        pr["head"]["sha"]
        for pr in pulls
        if pr["merged_at"] is not None
        and pr["merge_commit_sha"] == origin
        and pr["base"]["ref"] == "main"
        and pr["base"]["repo"]["full_name"] == repo
        and pr["head"]["ref"] == "automation/release"
        and (pr["head"]["repo"] or {}).get("full_name") == repo
        and pr["user"]["login"] == author
        and pr["title"] == f"chore(release): {tag}"
    ]
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{40}", matches[0]):
        raise ValueError(f"{tag} did not originate in its merged automation release PR")
    return matches[0]


def verify_source(repo, candidate, author):
    if not re.fullmatch(r"[0-9a-f]{40}", candidate):
        raise ValueError("Expected a full candidate commit SHA")
    version = manifest_version(candidate)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("Invalid Cargo package version for a release tag")
    tag = f"v{version}"
    tags = api(repo, f"git/matching-refs/tags/{tag}")
    if any(ref["ref"] == f"refs/tags/{tag}" for page in tags for ref in page):
        return

    origin = version_origin(candidate, version)
    pulls = api(repo, f"commits/{origin}/pulls")
    head = proposal_head((pr for page in pulls for pr in page), repo, author, origin, tag)
    proposal, = api(repo, f"commits/{head}")
    merged, = api(repo, f"commits/{origin}")
    if not all(commit["commit"]["verification"]["verified"] for commit in (proposal, merged)):
        raise ValueError(f"{tag} needs a verified proposal and merge signature")
    if (
        proposal["parents"][0]["sha"] != merged["parents"][0]["sha"]
        or proposal["commit"]["tree"]["sha"] != merged["commit"]["tree"]["sha"]
    ):
        raise ValueError(f"{tag} merged with a different base or tree than its release proposal")


if __name__ == "__main__":
    try:
        verify_source(os.environ["GITHUB_REPOSITORY"], *sys.argv[1:])
    except ValueError as error:
        sys.exit(str(error))
