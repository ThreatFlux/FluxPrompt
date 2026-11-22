#!/usr/bin/env bash
# Require untagged versions to originate in a signed automation release PR.
set -euo pipefail

candidate="$1"
author="$2"
repo="$GITHUB_REPOSITORY"

fail() {
  echo "$*" >&2
  exit 1
}

manifest_version() {
  git show "$1:Cargo.toml" |
    python3 -I -c 'import sys, tomllib; print(tomllib.load(sys.stdin.buffer)["package"]["version"])'
}

api() {
  gh api --paginate --slurp "repos/$repo/$1"
}

[[ "$candidate" =~ ^[0-9a-f]{40}$ ]] || fail "Expected a full candidate commit SHA"
version="$(manifest_version "$candidate")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "Invalid Cargo package version for a release tag"
tag="v$version"
tags="$(api "git/matching-refs/tags/$tag")"
if jq -e --arg ref "refs/tags/$tag" 'any(.[][]; .ref == $ref)' <<< "$tags" >/dev/null; then
  exit 0
fi

# Follow first parents so a proposal's side-branch commit cannot stand in
# for the merge that introduced this version to main.
history="$(git log --first-parent --full-history --format=%H "$candidate" -- Cargo.toml)"
origin=""
while IFS= read -r commit; do
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "Invalid manifest history commit"
  previous_version="$(manifest_version "$commit")"
  [[ "$previous_version" == "$version" ]] || break
  origin="$commit"
done <<< "$history"
[[ -n "$origin" ]] || fail "Cannot locate the version's origin on main"

pulls="$(api "commits/$origin/pulls")"
head="$(jq -er --arg origin "$origin" --arg repo "$repo" --arg author "$author" --arg tag "$tag" '
  [.[][] | select(.merged_at != null and .merge_commit_sha == $origin
    and .base.ref == "main" and .base.repo.full_name == $repo
    and .head.ref == "automation/release" and .head.repo.full_name == $repo
    and .user.login == $author and .title == ("chore(release): " + $tag))]
  | if length == 1 then .[0].head.sha else empty end
' <<< "$pulls")" || fail "$tag did not originate in its merged automation release PR"
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || fail "Invalid release proposal head"

proposal="$(api "commits/$head")"
merged="$(api "commits/$origin")"
jq -en --argjson proposal "$proposal" --argjson merge "$merged" '
  $proposal[0] as $p | $merge[0] as $m
  | $p.commit.verification.verified == true and $m.commit.verification.verified == true
    and ($p.parents[0].sha | type) == "string" and $p.parents[0].sha == $m.parents[0].sha
    and ($p.commit.tree.sha | type) == "string" and $p.commit.tree.sha == $m.commit.tree.sha
' >/dev/null || fail "$tag merged without verified signatures or with a different base or tree"
