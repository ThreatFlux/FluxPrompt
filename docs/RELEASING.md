# Releasing FluxPrompt

This runbook describes the current GitHub Actions workflows for the published `fluxprompt` crate.

## Release Contract

- `Cargo.toml` is the package-version source of truth.
- Release tags use `v<package-version>`, for example `v0.2.0`, and must be annotated tags whose commit is on `main`.
- The release workflow publishes one Rust library crate with crates.io trusted publishing.
- It does not build or attach platform binaries. It compiles and tests the library on every supported target and attaches the verified `.crate` archive, its file list, a CycloneDX SBOM, and a SHA-256 checksum for the crate and the SBOM to the GitHub release. The crate and the SBOM also get a signed build provenance attestation.
- crates.io releases cannot be deleted; a defective version can only be yanked and superseded.

## Required Access

No long-lived registry or GitHub token is stored for releases.

| Credential | Scope | Purpose |
| --- | --- | --- |
| ThreatFlux automation GitHub App (`TF_AUTOMATION_APP_ID` organization variable, `TF_AUTOMATION_APP_PRIVATE_KEY` organization secret) | `auto-release.yml` release job | Commit the version bump, push the annotated tag, and create the GitHub release. An App-pushed tag starts `release.yml` on its own. |
| crates.io trusted publishing (owner `ThreatFlux`, workflow `release.yml`, environment `crates-io`) | `release.yml` publish job (`id-token: write`) | Exchange the job's OIDC identity for a short-lived crates.io token with `rust-lang/crates-io-auth-action`. |
| GitHub Actions `GITHUB_TOKEN` and OIDC | `release.yml` GitHub release job (`contents: write`, `attestations: write`, `id-token: write`) | Attach the release assets, set the release notes, and record the build provenance attestation. |

The trusted publisher is bound to the workflow file name `release.yml` and the `crates-io` environment; renaming either breaks publication. Restrict the `crates-io` environment to release tags and protect `v*` tags with a repository ruleset so release tags cannot be created or moved by ordinary writers.

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
   npx --yes markdownlint-cli2@0.23.3
   python3 scripts/check_package.py
   cargo package --locked
   cargo publish --dry-run --locked
   ```

6. Inspect `cargo package --list` for credentials, generated reports, fixtures, local paths, and unintended large files.
7. Review dependency/audit results and any intentional exceptions.
8. Merge the release-preparation change to `main` only when the version is ready to publish.

## Automated Path

`.github/workflows/auto-release.yml` runs after `CI` and `Security Audit` complete on a push to `main` and calls the shared [ThreatFlux reusable auto-release workflow](https://github.com/ThreatFlux/github_actions). When both workflows succeeded for the `main` commit and there are `feat`, `fix`, or breaking commits since the last tag, it:

1. computes the next version from the Conventional Commit subjects (or the `version_bump` chosen in a manual dispatch);
2. stops if `Cargo.toml` is behind the latest release tag;
3. commits the version bump to `main`, pushes the annotated `v<version>` tag, and creates the GitHub release, all as the ThreatFlux automation App.

The App's tag push starts `release.yml` directly, so the reusable workflow does not dispatch it a second time. `chore`, `ci`, `build`, `docs`, and `test` commits never start a release.

Dispatch `auto-release.yml` with `dry_run` enabled to see the version and actions a release would take without writing anything.

`.github/workflows/release.yml` then:

1. verifies that the tag, any requested version, and `Cargo.toml` agree;
2. requires an annotated tag whose commit is reachable from `origin/main`;
3. builds the library in release mode for Linux (x86_64 glibc and musl, aarch64), macOS (Apple silicon and Intel), and Windows, runs the library tests on each native target, and runs the complete test suite (unit, integration, and doc tests) on x86_64 Linux;
4. generates a CycloneDX SBOM;
5. runs `scripts/check_package.py` and `cargo package --locked`;
6. skips publication if this version is already on crates.io with a byte-identical archive (so a rerun is safe) and fails if the registry archive differs, otherwise publishes with a trusted-publishing token from the `crates-io` environment;
7. checks that the packaged crate is byte-identical to the archive crates.io serves, records a signed build provenance attestation for the crate and the SBOM, and attaches the crate, its file list, the SBOM, and a SHA-256 checksum for each of the crate and the SBOM to the GitHub release, creating the release if it does not exist yet. When `CHANGELOG.md` has a `## [x.y.z]` section for the version, its text replaces the notes Auto Release generated, which list only `feat`, `fix`, and breaking commits.

Monitor every job. Do not assume that tag creation means a crate exists.

## Rehearsing a Release

Dispatch `release.yml` from `main` with `dry_run` enabled:

```bash
gh workflow run release.yml --ref main -f dry_run=true
```

A dry run builds every target, generates the SBOM, packages the crate, and runs `cargo publish --dry-run --locked`. It skips the `crates-io` environment, so its OIDC identity cannot be exchanged for a crates.io token, and it never creates a tag or GitHub release.

## Manual Path

A maintainer can release without Auto Release by pushing an annotated tag for the version already in `Cargo.toml` on `main`:

1. Verify the release commit and create the annotated tag if it does not exist:

   ```bash
   git tag -s v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

   If signed tags are not part of the project's established key-management process, use an annotated tag (`git tag -a`) rather than inventing an unverifiable signing identity.

2. Monitor the `release.yml` run created by the tag push.
3. Confirm the build, SBOM, crates.io publish, and GitHub release jobs complete in that order.

If GitHub did not create a run for the tag, first confirm that no release run is active. Only then dispatch `release.yml` using the tag as the workflow ref. Prefer rerunning a failed job over creating a concurrent or duplicate release run; a rerun skips a version that is already on crates.io.

## After Publication

1. Confirm the owner, version, license, repository link, README, and rendered rustdoc on crates.io/docs.rs.
2. Verify a fresh project can resolve the registry dependency and run the README quickstart.
3. Confirm the GitHub release points to the immutable tag and has accurate notes, then verify an attached asset and its attestation:

   ```bash
   gh release download v0.2.1 --repo ThreatFlux/FluxPrompt --pattern 'fluxprompt-0.2.1.crate*'
   sha256sum --check fluxprompt-0.2.1.crate.sha256
   gh attestation verify fluxprompt-0.2.1.crate --repo ThreatFlux/FluxPrompt
   ```

4. Announce only capabilities and compatibility supported by the shipped source and documentation.

Documentation publishing is separate: `.github/workflows/docs.yml` builds pull-request docs and deploys generated rustdoc from `main`.

## Failure and Recovery

### Verification Fails Before Publish

Fix the source on a new commit, choose a new version/tag if the existing tag already points to the failed release commit, and rerun the release. Do not silently move a public release tag.

### crates.io Publish Fails

No release assets are attached because that job depends on successful publication. Check that the crates.io trusted publisher still names `release.yml` and the `crates-io` environment, then rerun the failed job. The publish job skips a version that already reached crates.io; never attempt to upload different source under the same version.

### Published Crate Is Defective

1. Assess whether users need an immediate advisory or workaround.
2. Yank the affected crates.io version when continued selection would be harmful.
3. Keep the tag immutable so published source remains auditable.
4. Prepare and publish a corrected patch version.
5. Add an accurate changelog entry and security advisory when appropriate.

Deleting a GitHub release or tag does not remove a crates.io package and weakens provenance. Prefer an explicit deprecation/yank record and a new version.
