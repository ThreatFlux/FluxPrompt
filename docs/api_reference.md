# FluxPrompt API Reference

This page is the stable map to FluxPrompt's public API. For exhaustive item-level documentation, generate rustdoc locally with:

```bash
cargo doc --no-deps --all-features
```

Use this document to understand the main entry points and when to reach for each type.

## Primary Entry Points

### `FluxPrompt`

`FluxPrompt` is the main async interface for analyzing prompts and retrieving metrics.

Key constructors:

- `FluxPrompt::new(config)`: start from a `DetectionConfig`
- `FluxPrompt::from_preset(preset)`: start from an opinionated `Preset`
- `FluxPrompt::from_custom_config(custom_config)`: use a `CustomConfig`
- `FluxPrompt::from_file(path)`: load a JSON or YAML custom config from disk

Key methods:

- `analyze(&self, prompt) -> Result<PromptAnalysis>`
- `config(&self) -> &DetectionConfig`
- `metrics(&self) -> DetectionMetrics`
- `update_config(&mut self, config) -> Result<()>`

Minimal example:

```rust
use fluxprompt::{DetectionConfig, FluxPrompt, ResponseStrategy};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let config = DetectionConfig::builder()
    .with_security_level(7)?
    .with_response_strategy(ResponseStrategy::Block)
    .build();

let detector = FluxPrompt::new(config).await?;
let analysis = detector.analyze("Ignore all previous instructions").await?;

if analysis.is_injection_detected() {
    println!("Risk level: {}", analysis.risk_level());
}
# Ok(())
# }
```

## Configuration APIs

### `DetectionConfig`

`DetectionConfig` is the main runtime configuration type. It includes:

- `security_level`: preferred 0-10 tuning API
- `severity_level`: legacy compatibility layer
- `response_strategy`
- `pattern_config`
- `semantic_config`
- `preprocessing_config`
- `resource_config`
- `enable_metrics`
- `custom_config`

Important methods:

- `DetectionConfig::default()`
- `DetectionConfig::builder()`
- `DetectionConfig::validate()`
- `DetectionConfig::effective_security_level()`

### `DetectionConfigBuilder`

Use the builder when you want to stay on the lightweight configuration path.

Common methods:

- `with_security_level(level)`
- `with_security_level_struct(level)`
- `with_severity_level(level)`
- `with_response_strategy(strategy)`
- `with_custom_patterns(patterns)`
- `enable_semantic_analysis(enabled)`
- `with_timeout(duration)`
- `enable_metrics(enabled)`
- `with_custom_config(key, value)`
- `build()`

### `SecurityLevel` and `SeverityLevel`

- `SecurityLevel` is the preferred tuning model and represents a granular 0-10 scale.
- `SeverityLevel` is retained for backward compatibility and maps onto `SecurityLevel`.

If you are starting new work, prefer `SecurityLevel`.

### `ResponseStrategy`

`ResponseStrategy` defines what FluxPrompt does when an injection is detected:

- `Allow`
- `Block`
- `Sanitize`
- `Warn`
- `Custom(String)`

### `Preset`

`Preset` is the fastest way to start from a domain-oriented baseline. Current presets include:

- `ChatBot`
- `CodeAssistant`
- `CustomerService`
- `Educational`
- `Financial`
- `Healthcare`
- `Development`
- `Custom`

Use `FluxPrompt::from_preset(...)` when you want a sane default profile before adding custom rules.

### `CustomConfigBuilder` and `CustomConfig`

Reach for `CustomConfigBuilder` when you need more than the basic builder offers. It supports:

- metadata and naming
- feature toggles
- category thresholds and threat weights
- allowlists and denylists
- semantic-model settings
- resource limits and preprocessing controls
- rate limiting, locale, role, and context-aware options

Common entry points:

- `CustomConfigBuilder::new()`
- `CustomConfigBuilder::from_preset(...)`
- `CustomConfigBuilder::for_use_case(...)`
- `CustomConfigBuilder::high_performance()`
- `build()`
- `build_validated()`

`CustomConfig` can be serialized and loaded with:

- `to_json()` / `from_json(...)`
- `to_yaml()` / `from_yaml(...)`
- `save_to_file(path)` / `load_from_file(path)`

## Analysis Results

### `PromptAnalysis`

`PromptAnalysis` is returned by `FluxPrompt::analyze`. It contains the top-level result plus optional mitigated output.

Common methods:

- `detection_result()`
- `mitigated_prompt()`
- `is_injection_detected()`
- `risk_level()`
- `threat_types()`
- `add_metadata(key, value)`

### `DetectionResult`

`DetectionResult` is the lower-level detection-engine output embedded inside `PromptAnalysis`.

Common methods:

- `is_injection_detected()`
- `risk_level()`
- `confidence()`
- `threats()`
- `analysis_duration_ms()`
- `threat_types()`
- `highest_confidence_threat()`

### Threat Modeling Types

These types describe what was detected and how severe it is:

- `RiskLevel`
- `ThreatType`
- `ThreatInfo`
- `TextSpan`

`ThreatType` includes categories such as `InstructionOverride`, `RolePlaying`, `ContextConfusion`, `EncodingBypass`, `Jailbreak`, `SocialEngineering`, `DataExtraction`, `SystemPromptLeak`, and `CodeInjection`.

## Mitigation and Metrics

### Mitigation

Relevant public types:

- `MitigationEngine`
- `MitigationStrategy`

These types are useful if you need to reason about or extend how flagged content is handled after detection.

### Metrics

Relevant public types:

- `DetectionMetrics`
- `MetricsCollector`

`DetectionMetrics` exposes aggregate counters, timing statistics, confidence summaries, and percentile information. In most integrations you will access it through `FluxPrompt::metrics()`.

## Errors

Public error handling is exposed through:

- `FluxPromptError`
- `Result<T>`

Use these types for application-level error handling around configuration loading, timeouts, invalid inputs, and runtime detection failures.

## Where To Read Next

- [README.md](../README.md) for install and quick start
- [architecture.md](architecture.md) for system structure
- [detection_methods.md](detection_methods.md) for threat categories
- [security_guidelines.md](security_guidelines.md) for deployment guidance
