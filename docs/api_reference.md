# API Reference

This page maps the public API by task. Generated rustdoc is the item-level reference:

```bash
cargo doc --no-deps --open
```

Released API documentation is available on [docs.rs](https://docs.rs/fluxprompt). Generate documentation locally when reviewing an unreleased Git revision.

## Main Detector

### `FluxPrompt`

`FluxPrompt` is the top-level async interface.

| Method | Purpose | Important behavior |
| --- | --- | --- |
| `new(config)` | Construct from `DetectionConfig` | Validates the config before compiling regexes |
| `from_preset(preset)` | Construct from a built-in preset | Presets are starting values, not assurance profiles |
| `from_custom_config(config)` | Construct from `CustomConfig` | Consumes only its embedded `detection_config` at runtime |
| `from_file(path)` | Deserialize JSON/YAML and construct | Validates through `from_custom_config` |
| `analyze(prompt)` | Analyze one string | Uses a cooperative Tokio timeout and, when `enable_metrics` is `true`, records metrics on success; CPU-bound stages are not preempted |
| `config()` | Borrow the current configuration | Reflects the config on this detector instance |
| `metrics()` | Snapshot in-process observations | Contains detector outcomes, not ground-truth accuracy |
| `update_config(config)` | Rebuild engines on this instance | Existing clones keep their previous engine arcs |

For explicit validation:

```rust
use fluxprompt::{DetectionConfig, FluxPrompt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DetectionConfig::default();
    config.validate()?;
    let detector = FluxPrompt::new(config).await?;

    println!("level: {}", detector.config().effective_security_level());
    Ok(())
}
```

## Configuration

### `DetectionConfig`

`DetectionConfig` is the runtime configuration. Key methods are:

- `default()`
- `builder()`
- `validate()`
- `effective_security_level()`

The builder supports security/severity levels, response strategy, custom regexes, optional semantic checks, timeout, metrics metadata, and custom key/value metadata. `build()` does not validate.

Nested public configuration types live in `fluxprompt::config` and `fluxprompt::types`:

- `PatternConfig`
- `SemanticConfig`
- `ResourceConfig`
- `PreprocessingConfig`
- `DetectionConfigBuilder`

See [configuration](configuration.md) for which fields are currently enforced.

### `SecurityLevel`

`SecurityLevel::new(u8)` accepts 0 through 10. It exposes current threshold/weight calculations and enabled category names. Higher levels are more sensitive, not objectively “more secure.”

### `SeverityLevel`

`SeverityLevel` is the legacy four-level API. Prefer `SecurityLevel` for new integrations. The builder maps a legacy value to `security_level` when no explicit security level is set; runtime decisions use `security_level`.

### `ResponseStrategy`

`ResponseStrategy` controls mitigation text for detected input:

- `Allow`: warning prefix plus original text;
- `Block`: generated block message;
- `Sanitize`: heuristic transformation;
- `Warn`: generated warning message;
- `Custom(String)`: exact configured message.

It does not enforce control flow. The application must stop or alter the downstream operation.

### `Preset`

Current variants are `ChatBot`, `CodeAssistant`, `CustomerService`, `Educational`, `Financial`, `Healthcare`, `Development`, and `Custom`.

Presets select implementation defaults for thresholds, patterns, response text, preprocessing, and timeout. Their names do not claim domain compliance, measured accuracy, or suitability without application validation.

### `CustomConfig` and `CustomConfigBuilder`

`CustomConfigBuilder` creates named, serializable configs. Notable paths include:

- `new()` and `from_preset(...)`;
- identity methods such as `with_name`, `with_description`, `with_version`, and tags;
- core methods such as `with_security_level`, `with_response_strategy`, custom patterns, semantic settings, timeout, and preprocessing;
- advanced metadata methods for features, thresholds, roles, locales, context, and rate limits;
- `build()` and `build_validated()`.

`CustomConfig` supports:

- `validate()`;
- `to_json()` / `from_json(...)`;
- `to_yaml()` / `from_yaml(...)`;
- `save_to_file(path)` / `load_from_file(path)`;
- `merge_with(...)`, `summary()`, `touch()`, and `clone_with_name(...)`.

Deserialization does not validate automatically. `Features` and most `AdvancedOptions` are currently descriptors only; `FluxPrompt::from_custom_config` does not wire them into analysis. Read [configuration](configuration.md) before relying on them.

## Results

### `PromptAnalysis`

Returned by `FluxPrompt::analyze`. Useful methods:

- `detection_result()`
- `mitigated_prompt()`
- `is_injection_detected()`
- `risk_level()`
- `threat_types()`
- `add_metadata(...)`
- `set_duration(...)`

The public fields also include a generated ID, timestamp, embedded `DetectionResult`, optional mitigation text, and metadata. `PromptAnalysis::analysis_duration` is initialized from the engine duration recorded in `DetectionResult`.

### `DetectionResult`

The lower-level result provides:

- `is_injection_detected()`
- `risk_level()`
- `confidence()`
- `threats()`
- `analysis_duration_ms()`
- `threat_types()`
- `highest_confidence_threat()`

`DetectionResult::safe()` uses `RiskLevel::None`, no threats, and confidence `1.0`. Here that confidence represents the result's internal convention; it is not a measured probability that input is safe.

### Threat Types

`RiskLevel` values are `None`, `Low`, `Medium`, `High`, and `Critical`. The `is_injection` helper returns true for `Medium` and above.

`ThreatType` values include instruction override, role playing, context confusion, encoding bypass, jailbreak, social engineering, data extraction, system prompt leak, code injection, and `Custom(String)`.

`fluxprompt::types::ThreatInfo` contains the type, confidence, optional `TextSpan`, and metadata. Returned spans index the original input only when coordinates remain trustworthy; preprocessing and decoded-variant analysis omit spans and add provenance metadata instead.

## Metrics

`FluxPrompt::metrics()` returns a `DetectionMetrics` snapshot with counters, outcome breakdowns, confidence summaries, and latency observations. `detection_rate_percentage()` reports the share of analyzed requests the detector flagged.

It is not an accuracy measurement because the collector has no ground-truth labels. `estimated_false_positive_rate()` currently returns `None`.

Metrics are process-local and reset when the detector/collector is dropped. Set `DetectionConfig::enable_metrics` to `false` to skip recording. Custom threat names are aggregated under the stable `Custom` label so caller-controlled names cannot create unbounded metric cardinality or leak into metric keys.

`MetricsCollector` is public for integrations that need a separate collector. Record, snapshot, and reset operations are serialized so a snapshot does not combine pre-reset counters with post-reset samples. Its `reset()` method clears accumulated state.

## Lower-Level Detection and Mitigation

The crate publicly exposes:

- `DetectionEngine`, `PatternMatcher`, `HeuristicAnalyzer`, and `SemanticAnalyzer`;
- `MitigationEngine`, `TextSanitizer`, and `MitigationStrategy`;
- `ThreatContext` and `StrategySelector` through `fluxprompt::mitigation::strategies`.

These APIs expose implementation details and may change during `0.2.x`. Prefer `FluxPrompt` unless you need direct component-level testing.

`MitigationStrategy::removes_threat()` is a classification of transformation variants (`Remove` or `Replace`), not a guarantee that an attack has been neutralized.

## Errors

`FluxPromptError` includes configuration, detection, mitigation, regex compilation, I/O, serialization, runtime timeout, invalid-input, resource-limit, and internal variants. The crate-level `Result<T>` alias uses this error.

Do not return raw internal errors or untrusted prompt content to end users. Map them to application-specific responses and retain only the diagnostic detail your security/privacy policy permits.
