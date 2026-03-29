# Releasing

<!--
  RELEASING.md — What makes this document good:

  A release runbook should describe the exact release path this repository
  uses today, including quirks and limitations. It should be short enough to
  use during an actual release without guesswork.

  Best practices:
  - Document the default automated path first.
  - Include a manual fallback with concrete commands.
  - Call out the required secrets and what each one unlocks.
  - Note any workflow behavior that is easy to misunderstand.
-->

## Automated Release Path

FluxPrompt currently uses version-driven releases.

When a change is pushed to `main` and `Cargo.toml` contains a version that does not already have a matching Git tag, `.github/workflows/auto-release.yml`:

1. Reads the package version from `Cargo.toml`
2. Checks whether `v<version>` already exists
3. Creates and pushes the new tag
4. Creates a GitHub release with generated notes

That tag then triggers `.github/workflows/release.yml`, which:

- builds release artifacts for Linux x86_64, Windows x86_64, macOS x86_64, and macOS aarch64
- uploads those artifacts to the workflow and GitHub release
- publishes to crates.io if `CARGO_REGISTRY_TOKEN` is configured

Documentation publishing is separate. `.github/workflows/docs.yml` deploys generated docs on pushes to `main`, not on tags.

## Pre-Release Checklist

Before merging a version bump to `main`:

1. Run local validation:
   ```bash
   cargo fmt --check
   cargo clippy --all-features --all-targets -- -D warnings
   cargo test --all-features
   cargo test --no-default-features
   cargo test --doc --all-features
   cargo doc --no-deps --all-features
   cargo build --examples --all-features
   ```
2. Update `CHANGELOG.md` for user-visible changes.
3. Update README or operational docs if workflows, APIs, or requirements changed.
4. Bump the version in `Cargo.toml`.
5. Merge the change to `main`.

## Manual Release Fallback

Use this when you need to cut a release without relying on the auto-tag flow.

1. Complete the pre-release checklist.
2. Commit the version bump and changelog updates.
3. Create the tag locally:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
4. Confirm that `release.yml` starts on the tag push.

Important note: `release.yml` includes a `workflow_dispatch` entry, but the publish and GitHub release jobs are currently tag-gated. A manual workflow dispatch is useful for build-only validation, not for a full publish path.

## Required Secrets

| Secret | Purpose |
| --- | --- |
| `GITHUB_TOKEN` | Tag push, release creation, artifact upload |
| `CARGO_REGISTRY_TOKEN` | crates.io publish during tagged releases |

## Rollback

If a release is defective:

1. Delete the GitHub release.
2. Delete the tag: `git push --delete origin v0.1.0`
3. Yank the crates.io release if it was published.
4. Ship a corrected patch release with a new version number.
