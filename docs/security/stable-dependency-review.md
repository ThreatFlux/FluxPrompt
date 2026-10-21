# Stable dependency and security review

Reviewed 2026-10-21 from fetched main. Complete paginated inventories contain two open dependency PRs (108 and 109) and zero open code-scanning alerts. No alerts were dismissed. The rollup covers those dependency updates, refreshes all direct/dev crate requirements and compatible locked transitive packages to current stable releases, and updates Rust build/CI/release pins to official stable 1.99.1. The consumer MSRV remains 1.97.1.

Immutable Action pins were resolved from current upstream stable tags, including setup-node 7.1.0. Node 24 remains the supported LTS runtime. The existing pinned markdownlint-cli2 0.23.3 remains the current npm version. Cargo geiger and supply-chain tool pins move to 0.14.0 and 0.3.8 respectively. No Cargo feature or YAML compatibility alias is removed.

The repository-owned pre-push hook runs the full local CI gate. Validation covers formatting, strict Clippy, Markdown lint, package verification, full tests/examples/doctests/documentation, unchanged MSRV, Cargo audit and deny. Final results are recorded in the PR. No published container is maintained by this library repository.

Sources: [official Rust stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml), [crates.io sparse index](https://index.crates.io/config.json), [upstream setup-node releases](https://github.com/actions/setup-node/releases), [markdownlint-cli2 npm package](https://www.npmjs.com/package/markdownlint-cli2).

Completed locally: full `make ci-local`, unchanged Rust 1.97.1 MSRV, Cargo audit with warnings denied, Cargo deny, Actionlint and diff checks all passed. The full property suite passed all 19 tests with its unchanged generated-case counts and assertions. On the shared host the gate used `CARGO_BUILD_JOBS=2 TOKIO_WORKER_THREADS=2`; an earlier unbounded run was intentionally interrupted to reduce worker pressure.
