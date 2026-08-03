# Changelog

Notable user-visible changes are recorded here. This project uses the structure from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ThreatFlux/FluxPrompt/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ThreatFlux/FluxPrompt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ThreatFlux/FluxPrompt/releases/tag/v0.1.0
