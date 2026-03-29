# Contributing to FluxPrompt

Thanks for contributing. This guide covers local setup, validation, and pull request expectations for this repository.

## Code of Conduct

By participating in the project, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Prerequisites

- Rust `1.94.0` or later, with the repository pinned via `rust-toolchain.toml`
- Git
- Basic familiarity with async Rust and prompt-injection security concepts

## Local Setup

```bash
git clone https://github.com/ThreatFlux/FluxPrompt.git
cd FluxPrompt
cargo build --all-features
```

If you use the Makefile helpers, install the optional local tooling once:

```bash
make install-tools
```

## Development Workflow

1. Create a focused branch from `main`.
2. Make the smallest change set that solves the problem.
3. Add or update tests for any behavior change.
4. Update docs when the public API, workflows, or operator guidance change.
5. Run the relevant validation commands before opening a PR.

## Validation Commands

These commands mirror the current CI expectations:

```bash
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
npx --yes markdownlint-cli2
cargo test --all-features
cargo test --no-default-features
cargo test --doc --all-features
cargo doc --no-deps --all-features
cargo build --examples --all-features
```

Useful Make targets:

- `make ci-local`: local approximation of the CI workflow
- `make feature-test`: feature-combination checks
- `make audit`: dependency vulnerability scan
- `make doc-check`: strict rustdoc build
- `make markdownlint`: Markdown linting

## Documentation Expectations

- Keep `README.md` aligned with the current public API and repository workflows.
- Update [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- Prefer short, accurate docs over aspirational claims that are hard to verify.
- If you change release or disclosure behavior, update [docs/RELEASING.md](docs/RELEASING.md) or [SECURITY.md](SECURITY.md) in the same PR.

## Testing Expectations

- New features should include coverage for the expected behavior.
- Bug fixes should include a regression test when practical.
- Avoid flaky timing-dependent assertions.
- Keep examples compiling when their referenced APIs change.

## Pull Requests

- Use clear commit messages. Conventional-style prefixes such as `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, and `chore` are recommended.
- Use the pull request template and summarize motivation, scope, and testing.
- Call out any compatibility or security impact explicitly.
- Keep PRs focused. Split broad refactors unless the changes are tightly coupled.
- Ensure CI is green before requesting final review.

## Security

Public issues are fine for ordinary bugs and documentation gaps. For vulnerabilities, bypasses, or potentially exploitable behavior, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Getting Help

- Open an issue for bugs, documentation gaps, or feature proposals.
- Open a draft PR early if you want implementation feedback before the change is finished.

Thank you for helping keep FluxPrompt accurate, secure, and maintainable.
