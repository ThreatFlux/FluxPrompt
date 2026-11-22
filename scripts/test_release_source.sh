#!/usr/bin/env bash
# Run the real guard against a synthetic Git history and read-only API fixtures.
set -euo pipefail

guard="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/check_release_source.sh"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
cd -- "$fixture"
git init -q -b main
git config user.name "Release source fixture"
git config user.email "release-source@example.invalid"
git config commit.gpgsign false

commit_manifest() {
  printf '[package]\nversion = "%s"\n%s\n' "$1" "${3:-}" > Cargo.toml
  git add Cargo.toml
  git commit -qm "$2"
}

commit_manifest 0.2.5 'chore: baseline'
parent="$(git rev-parse HEAD)"
git checkout -qb automation/release
commit_manifest 0.2.6 'chore(release): v0.2.6'
proposal="$(git rev-parse HEAD)"
git checkout -q main
git merge -q --no-ff --no-edit automation/release
origin="$(git rev-parse HEAD)"
tree="$(git rev-parse 'HEAD^{tree}')"
commit_manifest 0.2.6 'feat: later change' '# feature'
candidate="$(git rev-parse HEAD)"

export GITHUB_REPOSITORY=ThreatFlux/FluxPrompt
author='threatflux-automation[bot]'
export fixture

gh() {
  case "$*" in
    "api --paginate --slurp repos/$GITHUB_REPOSITORY/git/matching-refs/tags/v0.2.6")
      cat "$fixture/tags.json" ;;
    "api --paginate --slurp repos/$GITHUB_REPOSITORY/commits/"*"/pulls")
      cat "$fixture/${4%/pulls}-pulls.json" ;;
    "api --paginate --slurp repos/$GITHUB_REPOSITORY/commits/"*)
      cat "$fixture/$4.json" ;;
    *) echo "Unexpected API request: $*" >&2; return 1 ;;
  esac
}
export -f gh

api_fixtures="$fixture/repos/$GITHUB_REPOSITORY/commits"
mkdir -p -- "$api_fixtures"
printf '[[]]\n' > tags.json
jq -n --arg origin "$origin" --arg proposal "$proposal" --arg author "$author" \
  --arg repo "$GITHUB_REPOSITORY" '
  [[{merged_at: "2026-01-01T00:00:00Z", merge_commit_sha: $origin,
     base: {ref: "main", repo: {full_name: $repo}},
     head: {ref: "automation/release", sha: $proposal, repo: {full_name: $repo}},
     user: {login: $author}, title: "chore(release): v0.2.6"}]]
' > "$api_fixtures/$origin-pulls.json"
jq -n --arg parent "$parent" --arg tree "$tree" '
  [{parents: [{sha: $parent}], commit: {tree: {sha: $tree}, verification: {verified: true}}}]
' > "$api_fixtures/$proposal.json"
cp -- "$api_fixtures/$proposal.json" "$api_fixtures/$origin.json"

verify() {
  bash "$guard" "$candidate" "$author"
}

expect_rejection() {
  local result
  if result="$(verify 2>&1)" || [[ "$result" != *"$1"* ]]; then
    echo "Expected rejection containing '$1', got: $result" >&2
    exit 1
  fi
}

verify
jq --arg parent "$candidate" '.[0].parents[0].sha = $parent' \
  "$api_fixtures/$proposal.json" > "$api_fixtures/$origin.json"
expect_rejection 'different base or tree'
printf '[[]]\n' > "$api_fixtures/$origin-pulls.json"
expect_rejection 'did not originate'
printf '[[{"ref":"refs/tags/v0.2.6"}]]\n' > tags.json
verify
