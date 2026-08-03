# Releasing FluxPrompt

This runbook describes the current GitHub Actions workflows for the published `fluxprompt` crate.

## Release Contract

- `Cargo.toml` is the package-version source of truth.
- Release tags use `v<package-version>`, for example `v0.2.0`.
- The release workflow publishes one Rust library crate.
- It does not build or attach platform binaries.
- A GitHub release is created only after crates.io publication succeeds.
- crates.io releases cannot be deleted; a defective version can only be yanked and superseded.

## Required Access

The repository needs a protected GitHub environment named `crates-io`. Restrict it to release tags and require a maintainer who did not initiate the deployment to approve publication. Protect `v*` tags with a repository ruleset so release tags cannot be created or moved by ordinary writers.

| Credential | Scope | Purpose |
| --- | --- | --- |
| GitHub Actions `GITHUB_TOKEN` | Repository workflow | Create the tag, dispatch the release workflow, and create the GitHub release |
| Organization Actions secret `CARGO_REGISTRY_TOKEN` | `crates-io` environment publish job | Authenticate `cargo publish` |

Limit the organization secret to repositories that publish Rust crates, rotate it under the organization credential policy, and migrate to crates.io trusted publishing when that repository integration is configured and verified.

## Prepare a Release

1. Decide the version using the public API, serialized configuration, and behavioral changes—not only commit labels.
2. Move relevant entries from `Unreleased` to `## [x.y.z] - YYYY-MM-DD` in `CHANGELOG.md` and update comparison links.
3. Set the same `version` in `Cargo.toml` and refresh `Cargo.lock` if needed.
4. Confirm README installation guidance and docs.rs links match the release being prepared.
5. Run the verification set from the repository root:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --locked
   cargo test --doc
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
   cargo build --examples
   python3 scripts/check_docs.py
   npx --yes markdownlint-cli2@0.23.2
   python3 scripts/check_package.py
   cargo package --locked
   cargo publish --dry-run --locked
   ```

6. Inspect `cargo package --list` for credentials, generated reports, fixtures, local paths, and unintended large files.
7. Review dependency/audit results and any intentional exceptions.
8. Merge the release-preparation change to `main` only when the version is ready to publish.

## Automated Path

`.github/workflows/auto-release.yml` watches changes to `Cargo.toml` on `main` and can also be dispatched manually from `main`. It rejects any other ref and stops if `main` advances while the package is being verified. It:

1. reads the package version;
2. checks whether `v<version>` already exists;
3. creates and pushes an annotated tag when it is missing;
4. explicitly dispatches `release.yml` at that tag with the same version.

The explicit dispatch is required because a tag pushed with the repository `GITHUB_TOKEN` does not trigger another workflow run by itself.

`.github/workflows/release.yml` then:

1. verifies that the tag, requested version, and `Cargo.toml` agree;
2. requires an annotated tag whose commit is reachable from `origin/main`;
3. runs the test suite;
4. runs `scripts/check_package.py`;
5. runs `cargo package --locked`;
6. runs `cargo publish --dry-run --locked`;
7. waits for approval in the protected `crates-io` environment and publishes with its scoped secret;
8. creates a GitHub release with commit-derived notes after publishing succeeds.

Monitor every job. Do not assume that tag creation means a crate or GitHub release exists.

## Manual Path

Normal `v*` tag pushes trigger `release.yml`. A maintainer can also dispatch that workflow manually, but publishing and GitHub-release jobs are tag-gated. Use one trigger per release; do not dispatch a second run after a normal tag push.

To publish manually:

1. Verify the release commit and create the annotated tag if it does not exist:

   ```bash
   git tag -s v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

   If signed tags are not part of the project's established key-management process, use an annotated tag (`git tag -a`) rather than inventing an unverifiable signing identity.

2. Monitor the `release.yml` run created by the tag push and approve its `crates-io` environment deployment after reviewing the verified package.
3. Confirm the verification, crates.io publish, and GitHub release jobs complete in that order.

If GitHub did not create a run for the tag, first confirm that no release run is active and that the version is still unpublished. Only then dispatch `release.yml` using the tag as the workflow ref and the unprefixed version as the input. Prefer rerunning a failed job over creating a concurrent or duplicate release run.

Dispatching the workflow on a branch is useful only for verification; tag-gated publish and release jobs will not run.

## After Publication

1. Confirm the owner, version, license, repository link, README, and rendered rustdoc on crates.io/docs.rs.
2. Verify a fresh project can resolve the registry dependency and run the README quickstart.
3. Confirm the GitHub release points to the immutable tag and has accurate notes.
4. Announce only capabilities and compatibility supported by the shipped source and documentation.

Documentation publishing is separate: `.github/workflows/docs.yml` builds pull-request docs and deploys generated rustdoc from `main`.

## Failure and Recovery

### Verification Fails Before Publish

Fix the source on a new commit, choose a new version/tag if the existing tag already points to the failed release commit, and rerun the release. Do not silently move a public release tag.

### crates.io Publish Fails

No GitHub release is created because it depends on successful publication. Determine whether the version reached crates.io before retrying. If it did, never attempt to upload different source under the same version.

### Published Crate Is Defective

1. Assess whether users need an immediate advisory or workaround.
2. Yank the affected crates.io version when continued selection would be harmful.
3. Keep the tag immutable so published source remains auditable.
4. Prepare and publish a corrected patch version.
5. Add an accurate changelog entry and security advisory when appropriate.

Deleting a GitHub release or tag does not remove a crates.io package and weakens provenance. Prefer an explicit deprecation/yank record and a new version.
