# Frequently Asked Questions

## Is FluxPrompt Available on crates.io?

Yes. The official package is [`fluxprompt`](https://crates.io/crates/fluxprompt), with generated API documentation on [docs.rs](https://docs.rs/fluxprompt). Commit `Cargo.lock` in applications and review dependency updates.

## Is FluxPrompt a Prompt-Injection Firewall?

No. It returns advisory signals and optional response text for a string supplied by the caller. The host application must enforce the result, constrain tools, authorize actions, and validate outputs. It can miss attacks and flag benign text. Start with the [threat model](threat-model.md).

## Does “Semantic Analysis” Use a Model or Embeddings?

No. The optional component currently named `SemanticAnalyzer` uses keyword and structure heuristics. It does not load `model_name`, compute embeddings, or make network requests.

## Which Constructor Should I Use?

Use `FluxPrompt::new` with `DetectionConfig` for most integrations. Use `from_preset` for an implementation-defined starting config and `from_custom_config` for a serializable wrapper. Constructors validate their configuration. For file-backed configuration, you may still load and validate explicitly when you want to inspect warnings before construction.

## How Should I Choose a Security Level?

Evaluate levels against representative benign and adversarial inputs from your own application. Higher values lower thresholds and enable more categories, which can increase both detection and false positives. Repository fixture rates are not a substitute for application calibration.

## What Does `Block` Actually Block?

Nothing by itself. For a flagged input, `ResponseStrategy::Block` puts a generated block message in `mitigated_prompt`. Your code must stop the downstream model/tool call. See the [quickstart](../README.md#quick-start).

## Is Sanitized Text Safe to Send to a Model?

Not necessarily. Sanitization is a lossy heuristic transformation. Treat the result as untrusted, validate it again, and keep downstream capabilities constrained. For high-impact paths, rejection or review is usually easier to reason about.

## Can I Detect Indirect Injection in Retrieved Documents?

You can pass retrieved text to `analyze`, ideally one provenance-preserving segment at a time. FluxPrompt does not fetch documents, distinguish trusted from untrusted segments, or automatically inspect a retrieval pipeline.

## Does It Track a Conversation?

No. Each call receives one string. `CustomConfig` contains context/history-shaped metadata, but the current runtime does not consume it. Cross-turn policy must be implemented by the host.

## Do `Features` Toggles Disable Individual Detectors?

Not when they exist only in `CustomConfig.features`. Those values are serialized descriptors in the current release. Runtime behavior comes from the embedded `DetectionConfig`, including selected pattern categories and `semantic_config.enabled`.

## Are Custom Allow/Deny Lists and Rate Limits Enforced?

No. Those `AdvancedOptions` fields are stored and partially validated but are not consumed by `FluxPrompt::from_custom_config`. Enforce them in your application or translate supported values into `DetectionConfig` yourself.

## Does `max_concurrent_analyses` Limit Concurrency?

No. `analysis_timeout` is a cooperative Tokio timeout and cannot preempt CPU-bound stages that do not yield; it is not a hard wall-clock bound. The concurrency, memory, and cache-size fields are not hard limits either. Use a semaphore or worker pool, service-level limits, and process isolation when strict preemption is required.

## Are Metrics an Accuracy Measurement?

No. Metrics report detector outcomes and timing. The collector has no ground-truth labels, and `estimated_false_positive_rate()` returns `None`. Measure false positives and negatives using reviewed application data.

## Can I Share a Detector Across Tasks?

Yes. `FluxPrompt` is cloneable and its clones share engines and metrics. Be careful with `update_config`: updating one clone replaces engines only on that instance; existing clones retain their previous engines.

## Why Did a Security Discussion Get Flagged?

Rule-based detectors can match quoted attacks, documentation, source code, role-play, and legitimate security research. Add such inputs to your benign calibration set, tune deliberately, and provide a review/retry path rather than assuming every match is malicious.

## How Do I Report a Bypass or Vulnerability?

Use GitHub private vulnerability reporting when available, or email `security@threatflux.ai`. Do not publish a working bypass or exploit before maintainers can triage it. See [SECURITY.md](../SECURITY.md).

## Where Is the Full API Documentation?

Generate rustdoc for the exact revision you use:

```bash
cargo doc --no-deps --open
```

The [API reference](api_reference.md) explains the main paths and behavioral caveats.
