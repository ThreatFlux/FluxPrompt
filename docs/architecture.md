# Architecture

FluxPrompt is an in-process Rust library. It accepts one text string per analysis and returns a structured analysis result plus optional mitigation text. It does not proxy an LLM request or call an external model.

## Component Map

```text
application
    |
    v
FluxPrompt
    |-- DetectionEngine
    |     |-- preprocessing
    |     |-- PatternMatcher
    |     |-- HeuristicAnalyzer
    |     `-- SemanticAnalyzer (optional keyword/structure checks)
    |-- MitigationEngine
    |     `-- TextSanitizer
    `-- MetricsCollector
```

The main modules are:

| Module | Responsibility |
| --- | --- |
| `lib` | `FluxPrompt` lifecycle, orchestration, shared state, and top-level API |
| `config` | Runtime configuration, security levels, response strategies, and builder |
| `detection` | Pattern, heuristic, optional semantic, decoding, aggregation, and scoring logic |
| `mitigation` | Response text and heuristic sanitization for flagged inputs |
| `types` | Risk, threat, span, preprocessing, and analysis result types |
| `metrics` | In-process counters, breakdowns, confidence observations, and latency samples |
| `presets` | Built-in starting `DetectionConfig` values |
| `custom_config` | Serializable configuration wrapper and advanced metadata |
| `config_builder` | Builder for `CustomConfig` and its metadata |
| `features` | Serializable feature descriptors used by custom configurations |

## Construction

`FluxPrompt::new` clones the supplied `DetectionConfig` into its components:

1. `DetectionConfig::validate` checks runtime invariants.
2. `PatternMatcher` compiles the selected built-in and custom regular expressions.
3. `SemanticAnalyzer` is allocated only when `semantic_config.enabled` is true.
4. `HeuristicAnalyzer` receives a configuration clone.
5. `MitigationEngine` constructs a `TextSanitizer`.
6. `MetricsCollector` starts with empty in-memory state.

Construction is async because the public component APIs are async. The current implementation does not perform model downloads or network I/O during construction.

`FluxPrompt::from_preset` converts a `Preset` to a `DetectionConfig`. `from_custom_config` extracts the embedded `detection_config`. `from_file` reads JSON or YAML into a `CustomConfig` and then follows the same path.

## Analysis Flow

`FluxPrompt::analyze` delegates to `DetectionEngine::analyze` and then, when the result is flagged, asks `MitigationEngine` to produce text:

```text
input text
   |
   +-- empty? ------------------------------> internal not-flagged result
   |
   +-- over max byte length? ---------------> InvalidInput error
   |
   v
configured preprocessing
   |
   v
pattern checks -> heuristic checks -> optional keyword/structure checks
   |
   v
decoded-variant pattern checks -> combination/context adjustments
   |
   v
risk score and configured threshold
   |
   +-- not flagged -------------------------> result, no mitigation text
   |
   `-- flagged -> response strategy --------> result + mitigation text
                                                    |
                                                    v
                                 metrics recording when enabled
```

The analysis stages currently run in sequence under a Tokio timeout wrapper. That timeout is cooperative: CPU-bound stages that do not yield cannot be preempted and may run past the configured duration. Async methods make integration with Tokio services convenient, but do not imply concurrent detection or a hard wall-clock bound.

## Detection Components

### Pattern Matcher

Built-in rules are grouped into named categories. A security level selects the default categories unless `PatternConfig::enabled_categories` is provided. Custom regexes are compiled into a separate category.

The matcher configures case-insensitive regexes by default and records the first match for each matching regex. The engine retains `TextSpan` values only when they can be verified against the caller's unchanged input; it omits them and records provenance metadata after coordinate-changing preprocessing or decoded-variant analysis.

### Heuristic Analyzer

The heuristic analyzer inspects entropy, repetition, text structure, selected linguistic markers, and encoding-like content. It adjusts some signals when text appears benign. These rules are deterministic implementation heuristics; their confidence values are not calibrated probabilities.

### Optional Semantic Analyzer

The type currently named `SemanticAnalyzer` performs phrase, keyword, and structure checks. It does not load embeddings, use the configured `model_name`, or make a model request. It is disabled by default.

### Preprocessing and Decoding

Preprocessing can remove most control characters and apply limited URL/Base64 decoding. The engine also creates a bounded set of decoded variants for pattern re-analysis. This is not canonical parsing of every encoding or Unicode normalization form.

See [detection methods](detection_methods.md) for implemented details and limitations.

## Scoring and Decisions

Each threat has a type and confidence value. The engine applies type weights, security-level scaling, category adjustments, threat-diversity bonuses, and configured thresholds to derive a `RiskLevel`.

`RiskLevel::is_injection` returns true for `Medium`, `High`, and `Critical`; `Low` is not treated as a detected injection by that method. Confidence is the maximum adjusted signal confidence, not the final risk score and not a statistical probability.

The exact scoring formula is implementation detail and may change before a stable release. Integrations should branch on documented result methods rather than duplicate thresholds.

## Mitigation Is Data, Not Enforcement

For flagged input, the mitigation engine returns a string based on `ResponseStrategy`. `FluxPrompt` places that string in `PromptAnalysis::mitigated_prompt`. Localized sanitization uses only verified spans with valid UTF-8 boundaries and matching content, then applies broader cleanup; threats without a trustworthy span require non-local transformations.

The library does not cancel downstream work, erase the caller's original buffer, or prevent another component from sending the original input. The host application owns the enforcement branch. Sanitized output is also untrusted and should be validated before use.

## Concurrency and State

`FluxPrompt` is cloneable. Clones share detection, mitigation, and metrics components through `Arc`; metrics use concurrent maps and atomic counters behind an async lock at the top level.

`update_config` requires `&mut self` and replaces the detection and mitigation engines on that instance. Existing clones continue using the engines they already hold, while the metrics collector remains shared. For atomic service-wide policy changes, construct a new detector and swap it using application-level coordination.

The current runtime does not enforce `max_concurrent_analyses`, `max_memory_mb`, `pattern_cache_size`, custom-config rate limits, or role/context rules. Apply those controls around the library.

## I/O and Data Retention

Normal analysis is local and performs no network I/O. `CustomConfig::load_from_file` and `save_to_file` are the file-system entry points. The Ollama example performs network requests, but that behavior is outside the library.

Metrics retain aggregate counters and a rolling set of timing/confidence observations in memory. FluxPrompt does not intentionally store complete prompt bodies in metrics. Application tracing and error handling can still expose sensitive data if configured carelessly; see [security guidelines](security_guidelines.md).

## Extension Boundaries

Detector traits are not currently exposed as a stable plug-in interface. Extension is primarily through custom regular expressions and configuration. Adding a new built-in detector requires a source change in `src/detection` and corresponding tests, threat-model updates, and calibration evidence.
