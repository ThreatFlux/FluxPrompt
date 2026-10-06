# Changelog

Notable user-visible changes are recorded here. This project uses the structure from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-10-06

This release does not change the public API or detection behavior. It raises the minimum versions of the direct dependencies to their current stable releases (for example `tokio` 1.53.2, `serde` 1.0.229, and `regex` 1.13.1) and refreshes the toolchain and release pipeline.

### Changed

- Updated the development toolchain to Rust 1.99.0, stable dependencies, and GitHub Actions while retaining Rust 1.97.1 as the minimum supported version.
- Added explicit CI compiler verification and an MSRV compatibility lane, and a worktree-specific pre-push local CI gate.
- Release automation now publishes to crates.io with trusted publishing (OIDC) instead of a stored registry token, cuts releases as the ThreatFlux automation GitHub App, builds the library for every supported target and runs its tests on each native target (the x86_64 musl target is build-only), attaches the verified crate, checksum, and CycloneDX SBOM to the GitHub release, and supports `dry_run` rehearsals of both release workflows.
- Coverage uploads to Codecov with OIDC instead of a stored token.
- GitHub releases now carry a SHA-256 checksum for both the crate and the SBOM, a signed build provenance attestation for each, and notes taken from this changelog; the attached crate is checked to be byte-identical to the one published on crates.io.

## [0.2.0] - 2026-08-03

### Added

- Explicit threat model, configuration behavior guide, and curated examples guide.
- Dependency-free documentation check for local Markdown links and README quickstart synchronization.
- Cargo package allowlist and packaged-Markdown link validation.

### Changed

- Updated the maintained Rust toolchain and documented minimum version to 1.97.1.
- Reworked user and API documentation to distinguish advisory detection from host-application enforcement.
- Documented the current keyword/structure implementation behind optional semantic analysis.
- Documented which `CustomConfig` and resource fields are metadata rather than runtime controls.
- Replaced unsupported performance, accuracy, compliance, and production-readiness claims with source-backed behavior and limitations.
- Updated vulnerability reporting to use GitHub private reporting or `security@threatflux.ai` without undocumented response-time promises.
- Added crates.io installation, version-pinning, and release-provenance guidance.
- Updated direct dependencies, migrated YAML support to `yaml_serde` 0.10, reduced Tokio's runtime feature set, and removed unused runtime dependencies.
- Retained the historical `metrics` and `experimental` Cargo features as compatibility no-ops while simplifying the documented build matrix.
- Reframed `ValidationStatus::checksum` as a non-security change marker and expanded it to cover the canonical configuration representation.
- Reworked release automation around verification and publication of the library crate, main-branch tag provenance, and a protected crates.io environment instead of nonexistent platform binaries.

### Fixed

- Kept semantic-analysis truncation on valid UTF-8 boundaries.
- Validated runtime configuration when constructing or updating a detector.
- Honored `enable_metrics` when recording detection metrics.
- Prevented metrics samples recorded in the same millisecond from overwriting one another, bounded rolling sample retention and custom-label cardinality, and serialized record/snapshot/reset operations.
- Prevented tracing spans from recording raw prompt arguments by default.
- Propagated measured analysis duration to the top-level `PromptAnalysis` result.
- Preserved UTF-8 boundaries when truncating semantic input, preprocessed text, and sanitized output.
- Kept modern `SecurityLevel` values authoritative in builders and mixed serialized fields while preserving legacy direct-struct behavior, mapped legacy-only serialized configurations, and rejected out-of-range levels during deserialization.
- Rejected disabled `CustomConfig` values at detector construction.
- Enabled the `jailbreak_comprehensive` category at security level 10.
- Validated custom regexes and the configured maximum pattern count before construction, and made case-insensitive matching preserve original-text span coordinates.
- Omitted untrustworthy spans after coordinate-changing preprocessing/decoding and required valid boundaries/content before localized sanitization.
- Corrected Base64 predicate precedence, Unicode-aware similarity helpers, and reverse-span length underflow.

### Removed

- Stale report-generating examples, misleading non-target custom-configuration sketches, and obsolete Ollama test runners/fixtures and shell wrappers.
- Unsupported compliance/model metadata from built-in presets.

## [0.1.0] - 2026-03-29

### Added

- Initial GitHub release of the async `FluxPrompt` API.
- Built-in regular-expression and heuristic detectors with configurable thresholds.
- Optional keyword-and-structure checks exposed through `SemanticAnalyzer`.
- Response-text generation, heuristic sanitization, in-process metrics, presets, and JSON/YAML custom configuration.
- Tests, examples, benchmarks, and initial project documentation.

FluxPrompt 0.1.0 was released as a GitHub tag. It was not published to crates.io.

[Unreleased]: https://github.com/ThreatFlux/FluxPrompt/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/ThreatFlux/FluxPrompt/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ThreatFlux/FluxPrompt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ThreatFlux/FluxPrompt/releases/tag/v0.1.0
