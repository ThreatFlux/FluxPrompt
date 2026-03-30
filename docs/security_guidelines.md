# FluxPrompt Security Guidelines

This document covers deployment and operational guidance for running FluxPrompt safely in production. It focuses on the current API and avoids environment-specific assumptions that can drift quickly.

## Table of Contents

- [Deployment Basics](#deployment-basics)
- [Configuration Strategy](#configuration-strategy)
- [Input and Output Handling](#input-and-output-handling)
- [Monitoring and Logging](#monitoring-and-logging)
- [Incident Response](#incident-response)
- [Compliance Notes](#compliance-notes)

## Deployment Basics

### Isolate the Service

- Run FluxPrompt separately from development and staging environments.
- Apply least-privilege access to runtime credentials, logs, and configuration files.
- Use network controls so only trusted upstream services can submit analysis requests.
- Treat configuration files as sensitive operational assets, especially when they contain custom threat rules or policy metadata.

### Use Hardened Runtime Images

- Prefer minimal base images.
- Run as a non-root user.
- Pin the Rust toolchain and rebuild images regularly.
- Scan images and dependencies as part of CI/CD.

Example container pattern:

```dockerfile
FROM rust:1.94-alpine AS builder
RUN adduser -D -s /bin/sh fluxprompt
WORKDIR /app
COPY . .
RUN cargo build --release --all-features

FROM alpine:3.20
RUN adduser -D -s /bin/sh fluxprompt
USER fluxprompt
COPY --from=builder /app/target/release/fluxprompt /usr/local/bin/
CMD ["fluxprompt"]
```

## Configuration Strategy

### Start from a Deliberate Baseline

Pick one of these paths:

- `DetectionConfig::default()` for a balanced baseline
- `DetectionConfig::builder()` for lightweight tuning
- `FluxPrompt::from_preset(...)` for domain-oriented defaults
- `CustomConfigBuilder` for advanced policy control and file-backed configs

Example baseline:

```rust
use fluxprompt::{DetectionConfig, FluxPrompt, ResponseStrategy};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let config = DetectionConfig::builder()
    .with_security_level(7)?
    .with_response_strategy(ResponseStrategy::Block)
    .enable_metrics(true)
    .build();

config.validate()?;
let detector = FluxPrompt::new(config).await?;
# let _ = detector;
# Ok(())
# }
```

### Validate Before Deploying

- Call `config.validate()` on generated configs before startup.
- Keep `security_level`, `response_strategy`, and timeout limits explicit in production-managed configs.
- Review custom patterns before rollout; overly broad regexes can increase false positives and CPU cost.
- If you use JSON or YAML configs, validate them in CI before shipping them to runtime.

### Tune Limits Conservatively

For stricter environments, prefer directly setting limits on a checked config:

```rust
use std::time::Duration;
use fluxprompt::DetectionConfig;

let mut config = DetectionConfig::default();
config.preprocessing_config.max_length = 10_000;
config.resource_config.analysis_timeout = Duration::from_secs(5);
config.resource_config.max_concurrent_analyses = 100;
config.validate()?;
```

## Input and Output Handling

### Input Handling

- Enforce request size limits before prompts reach FluxPrompt.
- Normalize trust boundaries: treat all user-supplied text as untrusted, even if it came through an internal system.
- Consider additional upstream rate limiting for public-facing APIs.
- Reject malformed or clearly abusive input before doing expensive downstream work.

### Output Handling

- Do not surface raw internal errors to end users.
- Avoid logging original prompt bodies unless the system is specifically designed for secure forensic capture.
- If you return mitigated text downstream, make sure callers know whether they are receiving original or transformed content.

### File-Backed Configurations

- Restrict write access to JSON and YAML config files.
- Treat configuration changes as deployable artifacts with code review, not ad hoc runtime edits.
- Keep a clear audit trail when updating custom patterns, thresholds, or presets.

## Monitoring and Logging

### Metrics

FluxPrompt exposes runtime metrics through `FluxPrompt::metrics()`. At minimum, monitor:

- total analyzed prompt volume
- detection rate
- average and percentile analysis latency
- shifts in risk-level breakdown
- sudden increases in specific threat categories

Example metric access:

```rust
let metrics = detector.metrics().await;
println!("Total analyzed: {}", metrics.total_analyzed());
println!("Detection rate: {:.1}%", metrics.detection_rate_percentage());
```

### Logging

- Log analysis outcomes, not full prompt contents, unless you have an explicit secure-retention requirement.
- Prefer structured logs with fields such as request ID, risk level, threat count, and latency.
- Separate operational logs from any incident-forensics pipeline.
- Retain logs only as long as required by your operational or regulatory needs.

## Incident Response

When FluxPrompt flags high-risk or critical content:

1. Block or quarantine the request according to your configured response strategy.
2. Capture the minimum evidence needed for investigation.
3. Alert the appropriate security or incident-response path.
4. Review whether new custom patterns, thresholds, or upstream controls are needed.
5. Record the change in version-controlled policy or configuration artifacts.

For repository-level vulnerability disclosure, follow [../SECURITY.md](../SECURITY.md).

## Compliance Notes

- Privacy-sensitive deployments should minimize prompt retention, minimize metrics content, and avoid logging directly identifying data where possible.
- Regulated environments should pair FluxPrompt with upstream authentication, authorization, audit logging, and data-classification controls.
- If you maintain domain-specific rules for healthcare, finance, or other regulated content, keep those rules versioned and reviewed like application code.
