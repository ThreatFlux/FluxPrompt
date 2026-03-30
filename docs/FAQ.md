# Frequently Asked Questions

<!--
  FAQ.md — What makes this document good:

  A FAQ should answer the questions people repeatedly ask in issues, reviews,
  and onboarding. Each answer should stand on its own and point to the deeper
  docs when more detail is needed.

  Best practices:
  - Use real questions contributors and users are likely to ask.
  - Keep answers short and concrete.
  - Point to deeper docs instead of duplicating them.
  - Update or remove questions when the product or workflow changes.
-->

## What's the fastest way to get started?

Start with [README.md](../README.md) and run the `basic_detection.rs` example. If you already have a Tokio runtime, you can create a detector with `DetectionConfig::default()` or a small builder configuration and call `FluxPrompt::analyze`.

## Which constructor should I use?

Use `FluxPrompt::new` when you already know the runtime configuration you want. Use `FluxPrompt::from_preset` for a domain-oriented baseline, `FluxPrompt::from_custom_config` for advanced policy objects, and `FluxPrompt::from_file` when your configuration lives in JSON or YAML.

## What's the difference between `SecurityLevel` and `SeverityLevel`?

`SecurityLevel` is the preferred API and gives you a 0-10 scale for finer control. `SeverityLevel` still exists for backward compatibility and maps onto the newer `SecurityLevel` model.

## Do I need semantic analysis enabled?

No. Semantic analysis is disabled by default, and the crate still performs pattern and heuristic analysis without it. Enable it when you want additional coverage and are prepared for the extra configuration and runtime cost.

## How do I build a more advanced policy than `DetectionConfig` supports?

Use `CustomConfigBuilder`. It adds feature toggles, allowlists, denylists, custom thresholds, rate limits, locale and role-specific settings, and file serialization helpers.

## Can I store configuration in a file?

Yes. `CustomConfig` supports JSON and YAML serialization, and `FluxPrompt::from_file(...)` loads supported files directly. See [api_reference.md](api_reference.md) for the relevant entry points.

## Where should I look for usage examples?

Start in the `examples/` directory. `basic_detection.rs`, `complete_demo.rs`, `policy_enforcement.rs`, `metrics_monitoring.rs`, and `ollama_integration.rs` cover most of the public surface.

## How do I reproduce CI locally?

Run the commands listed in [CONTRIBUTING.md](../CONTRIBUTING.md), or use `make ci-local` for the closest single-command approximation. For feature and security checks, `make feature-test` and `make audit` are the most useful follow-ups.

## Where is the full API documentation?

Use rustdoc for the authoritative item-level reference: `cargo doc --no-deps --all-features`. This repository's [api_reference.md](api_reference.md) is intended as a map, not a replacement for generated API docs.

## How do I report a vulnerability or prompt-bypass issue?

Do not open a public issue. Follow the reporting guidance in [SECURITY.md](../SECURITY.md) so the maintainers can triage it privately.
