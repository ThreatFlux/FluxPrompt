# Detection Methods

This document describes the implementation in the current source tree. FluxPrompt combines deterministic rules and heuristics; it does not provide a learned classifier or a calibrated probability of malicious intent.

## Pipeline Summary

For a non-empty input within the byte-length limit, the engine:

1. preprocesses the text according to `PreprocessingConfig`;
2. runs enabled built-in and custom regular expressions;
3. runs statistical, structural, linguistic, and encoding heuristics;
4. optionally runs additional keyword-and-structure checks;
5. creates decoded variants and re-runs pattern matching on them;
6. adds signals for selected combinations of threat types;
7. adjusts some signals for question-like or educational text;
8. maps the aggregate score to a `RiskLevel` using the security level.

The stages currently execute sequentially under a cooperative Tokio timeout. CPU-bound work that does not yield cannot be preempted, so `analysis_timeout` is not a hard wall-clock bound.

## Input Validation and Preprocessing

`DetectionEngine::analyze` returns `DetectionResult::safe()` for an empty string. That constructor is the internal not-flagged convention, not a safety determination. The engine rejects an input whose `str::len()` exceeds `preprocessing_config.max_length`; the limit is bytes, not Unicode scalar values or tokens.

When enabled, preprocessing:

- removes most control characters while keeping newlines and tabs;
- URL-decodes the text when decoding succeeds;
- decodes a whole input that looks like padded Base64 and contains valid UTF-8;
- caps the processed text at the configured byte length.

The field currently named `normalize_unicode` performs control-character filtering. It does not apply NFC/NFKC or confusable-character normalization. `preserve_formatting` is not currently consumed.

Decoding can change the text later used for spans and mitigation decisions. Keep the original input separately if your audit process requires it, but avoid logging it by default.

## Pattern Matching

Built-in regular expressions are grouped by behavior. Security levels progressively enable categories covering:

- instruction overrides and jailbreak phrasing;
- role-play and context-confusion language;
- common encoding-bypass markers;
- social-engineering, authority, urgency, and trust language;
- system-message impersonation and context-hijacking language;
- data-extraction and memory-extraction requests;
- staged escalation, hypothetical framing, and selected evasion phrases.

These names describe what a rule is intended to signal. A match does not establish that the sender is malicious, and a non-match does not establish safety.

### Category Selection

When `PatternConfig::enabled_categories` is `None`, the security level selects categories. Supplying a list replaces that automatic selection. Unknown category names do not load rules.

Custom regular expressions are compiled under a separate `custom` category:

```rust
use fluxprompt::DetectionConfig;

fn custom_rules() -> Result<DetectionConfig, Box<dyn std::error::Error>> {
    let config = DetectionConfig::builder()
        .with_custom_patterns(vec![
            r"(?i)reveal\s+tenant\s+secret".to_owned(),
            r"(?i)bypass\s+acme\s+policy".to_owned(),
        ])
        .build();

    config.validate()?;
    Ok(config)
}
```

Invalid custom regexes fail when a detector is constructed. Construction also fails when the selected built-in and custom regex count exceeds `max_patterns`.

### Case and Spans

Case-insensitive mode configures regex matching without lowercasing the analyzed string. `ThreatInfo::span`, when present in the top-level result, is a byte range into the caller's original input. The engine omits spans and adds provenance metadata when preprocessing or decoded-variant analysis would make those coordinates unreliable.

## Heuristic Analysis

The heuristic analyzer produces signals from implementation-defined thresholds, including:

- character entropy and special-character ratios;
- repetition, punctuation, and formatting patterns;
- unusual word structure and capitalization;
- Base64-, hex-, URL-, ROT13-, multi-layer-, and zero-width-character indicators.

It also calculates a simple benign-content score and reduces some confidences for content that resembles common questions, educational text, source code, or ordinary formatted prose.

These adjustments create trade-offs. Attackers can mimic benign indicators, and legitimate technical/security text can resemble an attack. The confidence numbers are rule scores, not observed false-positive probabilities.

## Optional Keyword-and-Structure Checks

`SemanticConfig::enabled` activates `SemanticAnalyzer`. The current implementation checks for:

- selected contradiction or redirection phrases;
- combinations of urgency/emotional and authority keywords;
- multiple context-switch phrases.

It does not compute embeddings, load `model_name`, understand conversation meaning, or contact an external model. The `similarity_threshold` field thresholds these heuristic scores despite its historical name.

## Decoded Variants

After the primary checks, the engine may generate URL-decoded, Base64-decoded, hex-decoded, ROT13, and control-character-filtered variants. It runs pattern matching—not every detector—against variants longer than five bytes, marks those threat records with `decoded_variant = true`, and omits spans because variant offsets do not index the original input.

The decoding logic is intentionally limited:

- Base64 and hex must satisfy shape checks and decode to UTF-8;
- embedded Base64 candidates use a regular-expression boundary;
- decoding is not recursive without bound;
- Unicode confusables, compression, encryption, custom ciphers, token smuggling, and many mixed encodings are out of scope.

## Combination Signals

The engine can add synthetic `ThreatType::Custom` records when selected threat types appear together, such as encoding plus an instruction override. This affects aggregate scoring but does not reconstruct attacker intent or prove that the signals refer to the same logical instruction.

## Risk and Confidence

Threat records carry a confidence value and a threat-type weight. The aggregate decision also depends on:

- the configured security level;
- category-specific adjustments;
- the number and diversity of threat types;
- benign/malicious indicator counts;
- the security level's minimum risk threshold.

The result contains two related but different values:

- `risk_level()` is the final categorical decision after thresholding;
- `confidence()` is the maximum adjusted contributing confidence.

`is_injection_detected()` is true only for `Medium`, `High`, or `Critical`. A `Low` result is not considered detected by that helper, though applications may choose a stricter policy.

The scoring formula is not a stable wire contract in `0.2.x`. Do not copy its constants into application policy.

## Evaluation Guidance

Repository demos use small, hand-authored fixtures. Their detection rates and “accuracy” output are descriptive only for those fixtures; they are not general efficacy measurements.

Before deployment:

1. Define the action that each risk level triggers.
2. Build separate benign and adversarial corpora representative of your application.
3. Include legitimate discussions of security, code, role-play, and encoded data.
4. Include direct and indirect injections from user input and retrieved content.
5. Track false positives and false negatives using reviewed ground truth.
6. Re-run the suite whenever the library, prompts, models, tools, or data sources change.
7. Keep a human-reviewed escape path for consequential false positives.

See the [threat model](threat-model.md) for trust boundaries and non-goals, and [security guidelines](security_guidelines.md) for defense-in-depth controls.
