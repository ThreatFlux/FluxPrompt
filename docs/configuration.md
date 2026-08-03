# Configuration

FluxPrompt has two configuration layers:

- `DetectionConfig` controls the behavior currently consumed by the detector and mitigation engine.
- `CustomConfig` wraps a `DetectionConfig` with serialization, names, tags, feature descriptors, and advanced policy-shaped metadata.

Builders do not all validate automatically. Detector constructors validate before creating engines, but calling `DetectionConfig::validate` or using `CustomConfigBuilder::build_validated` catches mistakes earlier and keeps validation close to configuration creation.

## Install From crates.io

FluxPrompt 0.2.0 requires Rust 1.97.1 or later:

```toml
[dependencies]
fluxprompt = "0.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Commit `Cargo.lock` in applications. Use `fluxprompt = "=0.2.0"` when policy requires an exact direct-dependency version, and review upgrades before deployment.

The `metrics` and `experimental` Cargo features are retained as compatibility no-ops for existing dependency declarations. Runtime metrics are controlled by `DetectionConfig::enable_metrics`; neither feature enables additional code.

## Choose a Constructor

| Constructor | Appropriate when |
| --- | --- |
| `FluxPrompt::new(DetectionConfig)` | You need runtime behavior with the smallest configuration surface |
| `FluxPrompt::from_preset(Preset)` | You want one of the built-in starting configurations |
| `FluxPrompt::from_custom_config(CustomConfig)` | You have validated a serialized or programmatically built custom config |
| `FluxPrompt::from_file(path)` | You want the library to deserialize and validate JSON/YAML during construction |

For file-backed configuration, an explicit load/validate step makes the boundary easy to test and inspect:

```rust,no_run
use fluxprompt::{CustomConfig, FluxPrompt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = CustomConfig::load_from_file("fluxprompt.yaml")?;
    config.validate()?;
    let detector = FluxPrompt::from_custom_config(config).await?;

    println!("level: {}", detector.config().effective_security_level());
    Ok(())
}
```

`FluxPrompt::from_file` follows the same validation path internally through `from_custom_config`.

## `DetectionConfig`

This is the recommended integration surface for new applications:

```rust
use std::time::Duration;
use fluxprompt::{DetectionConfig, ResponseStrategy};

fn application_policy() -> Result<DetectionConfig, Box<dyn std::error::Error>> {
    let config = DetectionConfig::builder()
        .with_security_level(6)?
        .with_response_strategy(ResponseStrategy::Block)
        .with_custom_patterns(vec![r"(?i)reveal\s+tenant\s+secret".to_owned()])
        .with_timeout(Duration::from_secs(2))
        .build();

    config.validate()?;
    Ok(config)
}
```

### Fields Consumed at Runtime

| Field | Current behavior |
| --- | --- |
| `security_level` | Adjusts enabled built-in categories, weights, and decision thresholds |
| `severity_level` | Legacy compatibility metadata; the builder maps it to `security_level` when no explicit security level is set |
| `response_strategy` | Selects the text returned in `mitigated_prompt` for a flagged input |
| `pattern_config` | Selects built-in categories/custom regexes and controls case behavior and the maximum compiled pattern count |
| `semantic_config.enabled` | Enables extra keyword-and-structure heuristics |
| `semantic_config.similarity_threshold` | Thresholds those extra heuristic results |
| `semantic_config.max_context_length` | Limits the text examined by those checks |
| `preprocessing_config.normalize_unicode` | Filters most control characters; it is not full Unicode normalization |
| `preprocessing_config.decode_encodings` | Enables limited URL and whole-input Base64 decoding |
| `preprocessing_config.max_length` | Rejects input above the configured byte length |
| `resource_config.analysis_timeout` | Wraps analysis in a cooperative Tokio timeout; it cannot preempt CPU-bound stages that do not yield |

Do not set both `security_level` and legacy `severity_level`. Prefer `security_level` for new code.

### Fields Not Yet Enforced

In the current `0.2.x` runtime:

- `resource_config.max_concurrent_analyses`, `max_memory_mb`, and `pattern_cache_size` are validated or carried as configuration but do not impose resource limits;
- `preprocessing_config.preserve_formatting` is not consulted by the preprocessing pipeline;
- `custom_config` key/value entries are not interpreted by the detector.

The timeout wrapper can observe its deadline only when the analysis future yields. The current CPU-bound stages may run past it, so `analysis_timeout` is not a hard wall-clock or CPU limit. Enforce concurrency, request size, CPU, memory, rate limits, and any strict deadline in the host service; use worker or process isolation when preemption is required.

Set `enable_metrics` to `false` to skip recording completed analyses in the detector's in-process collector. Calling `metrics()` still returns a snapshot, which remains empty until collection is enabled and analyses complete.

## Security Levels

`SecurityLevel` accepts values from 0 through 10. Higher levels enable more built-in pattern categories and lower decision thresholds. That makes the detector more sensitive, but it can also increase false positives.

The labels returned by `SecurityLevel::description` are qualitative implementation labels. They are not measured assurance levels. Build a versioned evaluation set with:

- representative benign user input;
- known attacks against your prompts, tools, and retrieval sources;
- encoded and multilingual variants relevant to your users;
- inputs that mention security topics for legitimate reasons.

Re-run calibration when changing FluxPrompt, models, system prompts, tools, or application policy.

## Response Strategies

For a flagged input, the selected strategy determines the value stored in `PromptAnalysis::mitigated_prompt`:

| Strategy | Returned text |
| --- | --- |
| `Allow` | Original input prefixed with a warning |
| `Block` | Generated block message; the original input is omitted |
| `Sanitize` | Heuristically transformed input |
| `Warn` | Generated warning message; the original input is omitted |
| `Custom(message)` | The configured message |

No strategy performs network or access-control enforcement. Check `is_injection_detected()` and decide whether to reject, quarantine, sanitize, or escalate before invoking a model or tool.

Sanitization is lossy and heuristic. It can change meaning and does not prove the transformed prompt safe. Re-analyze or apply application-specific validation before forwarding sanitized text.

## Optional “Semantic” Checks

Despite the current type name, `SemanticAnalyzer` does not load embeddings or an NLP model. It checks configured text for keyword combinations and structural phrases. `SemanticConfig::model_name` is retained as metadata and exposed by the analyzer, but it is not loaded or called.

Enable this path only after measuring it against your inputs:

```rust
use fluxprompt::DetectionConfig;

fn keyword_checks() -> Result<DetectionConfig, Box<dyn std::error::Error>> {
    let mut config = DetectionConfig::builder()
        .enable_semantic_analysis(true)
        .build();
    config.semantic_config.similarity_threshold = 0.6;
    config.validate()?;
    Ok(config)
}
```

## `CustomConfig`

Use `CustomConfigBuilder` for named, serializable configuration:

```rust
use fluxprompt::{CustomConfigBuilder, Preset, ResponseStrategy};

fn serialized_policy() -> Result<String, Box<dyn std::error::Error>> {
    let config = CustomConfigBuilder::from_preset(Preset::ChatBot)
        .with_name("support-chat-v1")
        .with_security_level(6)?
        .with_response_strategy(ResponseStrategy::Block)
        .add_custom_pattern(r"(?i)export\s+support\s+credentials")
        .build_validated()?;

    Ok(config.to_yaml()?)
}
```

`FluxPrompt::from_custom_config` rejects a configuration whose top-level `enabled` field is `false`, then passes `custom_config.detection_config` into the runtime. The following `CustomConfig` fields are persisted and partially validated, but do not independently alter analysis or enforce policy:

- `features` toggles;
- category threshold and threat-weight overrides;
- pattern allowlists and denylists;
- rate-limit settings;
- conversation-history/context settings;
- language, locale, role, and time-based settings;
- response templates and general metadata.

Applications may read and enforce these values themselves. Do not assume the detector has done so merely because the configuration validates.

## Configuration Updates

`FluxPrompt::update_config(&mut self, config)` rebuilds both detection and mitigation engines. Because it requires mutable access, coordinate updates at the service layer and decide whether in-flight requests should use the old or new instance. Validate the replacement before applying it.
