# Security Guidelines

FluxPrompt supplies advisory text-analysis results. Secure deployment depends on where analysis occurs, how the result is enforced, and what capabilities remain available to the model or agent.

Start with the [threat model](threat-model.md). This guide focuses on integration and operations.

## Put Enforcement Before Side Effects

Analyze untrusted content before it is added to model context, retrieval output, tool arguments, or an action queue. Branch explicitly on the result:

```rust
use fluxprompt::FluxPrompt;

async fn screen<'a>(
    detector: &FluxPrompt,
    input: &'a str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let analysis = detector.analyze(input).await?;

    if analysis.is_injection_detected() {
        return Err("request rejected by prompt policy".into());
    }

    Ok(input)
}
```

Do not begin an LLM request or tool operation concurrently with screening. `ResponseStrategy::Block` only generates text; it does not enforce this branch.

For indirect injection, analyze each untrusted retrieval/tool segment before composition where practical. Keep provenance labels so the application can apply different policies to system instructions, user input, and external content. Concatenating everything into one string erases the trust boundary FluxPrompt would need to reason about it.

## Validate Configuration

- Validate at startup and reject invalid configurations rather than falling back silently.
- Prefer immutable, version-controlled configuration reviewed with the application code.
- Avoid setting both `security_level` and legacy `severity_level`.
- Treat presets as starting points, not domain certifications or measured security profiles.
- Compile and exercise custom regexes in CI. Broad expressions can create false positives and CPU cost.
- Re-run application calibration after changing a level, pattern, response strategy, model, prompt, retrieval source, or tool.

See [configuration](configuration.md) for fields that are and are not consumed by the runtime.

## Enforce Resource Limits Outside the Crate

`analysis_timeout` wraps analysis in Tokio's cooperative timeout. The current CPU-bound detection stages may not yield before they finish, so the wrapper cannot preempt them and is not a hard wall-clock or CPU limit. Other resource-shaped fields are also not hard runtime controls in the current release.

At the service boundary:

- limit HTTP/body and prompt size before allocating or decoding it;
- bound concurrent analyses with a semaphore or worker pool;
- apply per-principal and per-source rate limits;
- use service-level CPU and memory limits;
- cap queue depth and shed load deliberately;
- apply an outer service deadline and use worker or process isolation where CPU-bound work must be preemptible;
- set downstream model/tool timeouts independently;
- test custom regexes against adversarial worst cases.

Do not rely on `CustomConfig` rate-limit fields or `ResourceConfig` concurrency/memory/cache values unless the host explicitly enforces them.

## Constrain Model and Tools

Controls that authorize by capability remain effective even when text detection fails:

- give each tool a narrow, allowlisted operation set;
- derive authorization from authenticated application state, never model text;
- validate tool arguments against typed schemas and business rules;
- restrict network destinations and file-system paths;
- isolate code execution and apply time/resource limits;
- require human confirmation for destructive, financial, permission-changing, or externally visible actions;
- validate outputs and apply data-egress policy before returning or acting on them.

System-prompt wording alone is not an authorization control.

## Treat Mitigated Text as Untrusted

`Sanitize` uses deterministic substitutions and formatting cleanup. It can remove benign meaning, leave malicious meaning, or create a new ambiguous prompt. If an application forwards sanitized text:

1. retain a decision ID separately for audit correlation;
2. re-run relevant validation on the transformed value;
3. present transformation clearly to a reviewing user when appropriate;
4. keep downstream capabilities least-privileged;
5. never treat successful sanitization as proof of safety.

For high-impact actions, rejection or quarantine is generally easier to reason about than automatic rewriting.

## Logging and Privacy

Prompt text can contain credentials, personal data, customer content, system instructions, or exploit details. Default operational telemetry should record outcomes rather than content:

- request/decision ID;
- library/configuration version;
- risk level and threat-category identifiers;
- analysis duration and enforcement action;
- source/provenance class without raw content.

If forensic prompt capture is necessary, use a separate access-controlled store with encryption, retention limits, audit logs, and redaction. Avoid putting raw input in general application logs, traces, metrics labels, exception messages, or alert titles.

Review the tracing subscriber and exporters used by the host. A dependency or older FluxPrompt revision may record function arguments; confirm behavior for the exact revision you deploy.

## Metrics and Alerting

`FluxPrompt::metrics()` reports detector activity, not attack prevalence or accuracy. A rising detection rate can mean attacks, a product change, a configuration change, or false positives.

Useful operational signals include:

- total analyses and errors;
- risk-level and threat-category distributions;
- latency and timeout changes;
- downstream action denials;
- reviewed false-positive/false-negative labels;
- configuration and library-version changes.

Do not include prompt text, user IDs, or high-cardinality secrets in metrics labels. Export snapshots to your own monitoring system if persistence is required; crate metrics are in-process state.

## Failure Policy

Choose behavior deliberately for each failure class:

| Failure | Possible policy considerations |
| --- | --- |
| Invalid configuration at startup | Fail startup and keep the last reviewed deployment |
| Invalid/oversized input | Return a bounded client-safe error; do not invoke downstream systems |
| Analysis timeout or internal error | Fail closed for high-impact paths; use a restricted fallback for lower-risk paths only if explicitly designed |
| Metrics/export failure | Avoid blocking security decisions solely for telemetry |
| Detector unavailable | Disable tool capabilities or route to review rather than silently bypassing policy |

Document the selected policy and test it. “Fail closed” can itself create an availability risk, so combine it with resource limits and operational recovery.

## Testing and Calibration

Maintain versioned tests that represent the deployment:

- benign inputs, including quoted attacks and security discussions;
- direct and indirect injections;
- obfuscated, encoded, multilingual, and long inputs;
- multi-turn sequences tested at the application layer;
- each tool and privilege boundary;
- model outputs that attempt unexpected tool actions;
- timeout, overload, and malformed-configuration behavior.

Keep evaluation and tuning data separate from production secrets. Repository example fixture rates are not substitutes for this work.

## Incident Response

When a suspected injection reaches or influences a sensitive action:

1. contain the affected session, credentials, tools, and queued actions;
2. preserve the minimum necessary evidence under your incident policy;
3. determine the input provenance and downstream capabilities involved;
4. inspect actions and data access, not only the detector decision;
5. add a regression case and improve capability controls before relying on a new regex;
6. rotate exposed credentials and notify affected parties when required;
7. report a FluxPrompt bypass privately if it indicates a library weakness.

Follow [SECURITY.md](../SECURITY.md) for repository vulnerability reporting.

## Supply-Chain Practices

- Commit `Cargo.lock` in deployed applications and review dependency changes.
- Run the repository's audit and policy checks.
- Verify the crates.io package, release tag, and source provenance appropriate to your environment.
- Rebuild from source in a controlled pipeline rather than relying on unverified artifacts.

The official registry package is [`fluxprompt`](https://crates.io/crates/fluxprompt).
