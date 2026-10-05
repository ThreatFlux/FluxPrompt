# Stable tooling refresh — 2026-10-05

FluxPrompt's development and release toolchain is Rust 1.99.0, released on
2026-10-01 according to the [official stable distribution manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml).
The public crate keeps version 0.2.0, edition 2024, and its Rust 1.97.1 minimum.
The `metrics` and `experimental` features, runtime behavior, and public API remain
unchanged.

## Dependencies and actions

Every direct registry dependency now selects the latest stable, non-yanked
release published on crates.io when verified on 2026-10-05. No direct dependency
needs an older compatibility line. The lockfile was refreshed within the existing
dependency graph and minimum Rust version; every selected registry release was
checked against its crates.io version metadata for prerelease and yanked status.

All six workflows use immutable action commit SHAs. Each SHA was resolved from
the upstream stable release and its action or reusable-workflow input schema was
reviewed. The maintained `dtolnay/rust-toolchain` action has no stable release tag;
its current upstream `master` commit is pinned. Updated releases include CodeQL
4.38.2, Codecov 7.1.1, `taiki-e/install-action` 2.87.25, Pages deployment 5.0.1,
and `softprops/action-gh-release` 3.0.3. Existing current action pins remain in use.

Cargo tools installed by the Makefile have explicit stable versions. Coverage
uses cargo-llvm-cov 0.9.1 and Codecov CLI 11.3.1; Markdown linting uses
markdownlint-cli2 0.23.3 in both local and hosted checks.

| Surface | Verified source | Chosen update | Compatibility and verification |
| --- | --- | --- | --- |
| Development Rust | [Stable distribution metadata](https://static.rust-lang.org/dist/channel-rust-stable.toml) | 1.97.1 → 1.99.0 | Actual compiler printed; strict Clippy, rustdoc, and tests use the pinned toolchain |
| Minimum Rust | [Cargo manifest](../Cargo.toml) | Retain 1.97.1 | Actual 1.97.1 locked all-target check passes; a hosted compatibility lane now enforces it |
| Registry crates | [crates.io API](https://crates.io/data-access) and individual release metadata | All 22 direct crates at latest stable; lockfile refreshed | All 266 registry lock entries checked stable/non-yanked; public features and source preserved |
| Actions | Upstream release and `action.yml`/reusable-workflow schemas | 49 immutable SHA references across six workflows | Compiler selectors, changed inputs, runner runtimes, and release gates reviewed; actionlint and yamllint pass |
| API contract | Fetched main `4c3eb107e8eba21e4a5ec9c366af998ebd22a41a` | Preserve public source, package metadata, and feature graph | cargo-semver-checks 0.51.0 passes 202 applicable checks; no semver update required |

## Compiler selection and validation

Rust jobs explicitly select Rust 1.99.0 and print their active toolchain, detailed
compiler version, and Cargo version. Compatibility jobs override that selector
for beta and Rust 1.97.1, so the repository toolchain file cannot accidentally
turn them into stable-only checks. Linux, Windows, and macOS coverage is retained.
The minimum-version lane checks all targets against the committed lockfile.

The local required gate remains `make ci-local`: formatting, strict Clippy,
Markdown and documentation contracts, package contents, release build, tests,
example compilation, doctests, and strict rustdoc. `make hooks-install` installs
that gate as a pre-push hook for the current worktree. Security auditing retains
an empty advisory ignore list, and no lint or scanner exception was added.

The native cargo-geiger 0.13.0 JSON inventory was also checked against the local
package identity and its metrics. It completed with diagnostics retained,
including two dependency parser warnings and generated files that the scanner
does not inspect. This inventory does not establish complete unsafe-code
coverage; it remains an informational tool.

Coverage and benchmark compilation retain their existing main-push-only hosted
policy; they are also checked locally for this refresh. Documentation publication,
crates.io publication, and GitHub releases retain their existing main/tag gates.
The reusable auto-release workflow remains the single release owner.

No Dockerfile is present in this repository. No remote model or billable provider
request is needed by the ordinary tests, and relevant provider keys are unset
during local validation. Live Ollama behavior and release publication are outside
this tooling refresh.
