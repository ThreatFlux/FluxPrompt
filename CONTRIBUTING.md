# Contributing to FluxPrompt

Contributions are welcome. Because FluxPrompt is security-adjacent, changes should be small enough to review, explicit about their threat-model impact, and backed by tests that include both malicious and benign cases.

By participating, follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities and consequential bypasses privately according to [SECURITY.md](SECURITY.md).

## Prerequisites

- Rust 1.97.1, pinned by `rust-toolchain.toml`, with Rustfmt and Clippy;
- Git;
- Python 3 for the dependency-free documentation consistency check;
- Node.js/npm only when running Markdownlint locally;
- optional Cargo tools for supply-chain, coverage, and semver checks.

The normal library and test suite do not require an API key or external model. The Ollama example requires a separately running Ollama instance.

## Set Up a Checkout

```bash
git clone https://github.com/ThreatFlux/FluxPrompt.git
cd FluxPrompt
cargo build
cargo test
```

Create a focused branch from current `main`. Keep generated reports, local configuration, credentials, model files, and build artifacts out of commits.

## Understand the Contract First

Before changing detector or mitigation behavior, read:

- [Threat model](docs/threat-model.md)
- [Detection methods](docs/detection_methods.md)
- [Architecture](docs/architecture.md)
- [Configuration behavior](docs/configuration.md)

FluxPrompt returns advisory signals. Avoid language or APIs that imply guaranteed prevention, calibrated probabilities, compliance, or automatic enforcement without evidence and implementation to support them.

## Development Workflow

1. Add a failing regression test or a small behavior test.
2. Make the narrowest implementation change that satisfies it.
3. Add benign counterexamples for new detection rules.
4. Update rustdoc, guides, examples, and the threat model when contracts change.
5. Add an entry under `CHANGELOG.md` → `Unreleased` for user-visible changes.
6. Run focused tests, then the full local checks.

Do not add real customer prompts, credentials, private system prompts, or unpublished exploit reports to fixtures. Minimize and synthesize reproductions.

## Local Checks

Run this full local validation before requesting review. It intentionally includes extra doctest and example checks beyond the primary CI job:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --doc --locked
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --examples
python3 scripts/check_docs.py
npx --yes markdownlint-cli2@0.23.2
python3 scripts/check_package.py
```

`make ci-local` runs the repository's local CI approximation. Inspect the Makefile and GitHub workflows when exact parity matters; security and coverage tools may require separate installation and can take longer.

Useful focused commands:

```bash
cargo test detection::
cargo test mitigation::
cargo test --test attack_vectors
cargo bench --no-run
```

Do not present a local benchmark or small fixture suite as general throughput, accuracy, or false-positive evidence. Record the machine, build profile, dataset, sample size, and command when performance data is relevant to a review.

## Detection-Rule Changes

A rule change should normally include:

- the attack behavior being signaled;
- one or more minimized adversarial fixtures;
- benign counterexamples, including quoted/documentary uses when relevant;
- expected threat type, risk behavior, and affected security levels;
- consideration of casing, Unicode, encoding, and input length;
- a note about compatibility or false-positive trade-offs.

Avoid rules tied only to a single published attack phrase when a bounded behavior-oriented expression is possible. Keep regexes reviewable and test their worst-case resource behavior.

## Public API and Configuration Changes

- Preserve the host application's enforcement responsibility in names and docs.
- Do not document a `CustomConfig` field as enforced until the runtime consumes it.
- Validate configuration at construction/update boundaries when introducing invariants.
- Treat serialization shape and public enum variants as compatibility-sensitive.
- Add rustdoc examples for new primary entry points and run doctests.
- Explain behavior changes under `CHANGELOG.md` → `Unreleased`.

The crate is pre-1.0, but compatibility still matters. Call out breaking changes rather than relying on the version number to make them invisible.

## Documentation Changes

- Prefer factual present-tense behavior over roadmap claims and superlatives.
- Link to one authoritative explanation instead of duplicating large sections.
- Keep README quickstart code identical to `examples/basic_detection.rs`; `scripts/check_docs.py` enforces this.
- Make every copied command runnable from the repository root.
- Label fixture-derived rates and timing as local observations.
- Update `docs/README.md` when adding or removing a durable guide.

## Pull Requests

Use the pull request template and include:

- the problem and why it belongs in FluxPrompt;
- implementation scope and deliberately excluded work;
- tests and commands run;
- API, configuration, threat-model, privacy, and compatibility impact;
- follow-up work that is genuinely separate.

Keep unrelated formatting, dependency, detector, and documentation changes in separate commits or pull requests where practical. Ensure CI passes before requesting review.

## Getting Help

Use a public issue for ordinary bugs, documentation gaps, and design proposals that contain no sensitive exploit detail. Open a draft pull request when concrete code is useful for discussion. Use the private paths in [SECURITY.md](SECURITY.md) for vulnerabilities or security-impacting bypasses.
