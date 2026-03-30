# Changelog

All notable changes to FluxPrompt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Root-level project governance docs with `SECURITY.md` and `CODE_OF_CONDUCT.md`
- A documentation index in `docs/README.md`
- Maintainer-facing FAQ and release runbook docs in `docs/FAQ.md` and `docs/RELEASING.md`

### Changed
- Rewrote the root README to match the current ThreatFlux repository, examples, and Rust `1.94.0` baseline
- Refreshed contributing guidance, issue and PR templates, and repository metadata URLs
- Replaced the stale API reference with a stable overview that matches the current public entry points

## [0.1.0] - 2026-03-29

### Added
- Async prompt-injection detection and mitigation APIs centered on `FluxPrompt`
- Built-in coverage for instruction overrides, jailbreaks, encoding bypasses, context hijacking, social engineering, and data extraction patterns
- Presets, custom configuration builders, metrics collection, examples, and architecture/security documentation

### Changed
- Established Rust `1.94.0` and the Rust 2024 edition as the maintained baseline
- Refreshed direct dependencies and CI/CD workflows to current stable versions

### Security
- Added input validation, mitigation, and deployment guidance for production use
