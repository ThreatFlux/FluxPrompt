#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
git config extensions.worktreeConfig true
git config --worktree core.hooksPath scripts/hooks
printf 'Installed the FluxPrompt pre-push local CI gate for this worktree.\n'
