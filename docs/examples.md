# Examples

All example targets should compile with:

```bash
cargo build --examples
```

Most run locally. The Ollama integration is the exception and requires a separate service. Example fixture results are demonstrations of current behavior, not measured security efficacy or production benchmarks.

## Start Here

### Basic Detection

```bash
cargo run --example basic_detection
```

[`basic_detection.rs`](../examples/basic_detection.rs) is the README quickstart. It constructs an explicit policy, validates it, analyzes one input, and shows the host-side enforcement branch.

### Custom Rules

```bash
cargo run --example custom_rules
```

[`custom_rules.rs`](../examples/custom_rules.rs) adds application-specific regular expressions. Review and test every expression against both benign and adversarial corpora before deployment.

### Serializable Configuration

```bash
cargo run --example custom_config
```

[`custom_config.rs`](../examples/custom_config.rs) builds and validates a named `CustomConfig`, round-trips it through YAML, and constructs a detector. It deliberately avoids advanced metadata that the current runtime does not enforce.

### Sensitivity Exploration

```bash
cargo run --example security_level_demo
cargo run --example level_calibration
```

These programs compare detector output across security levels using small, embedded fixture sets. Their percentages describe only those fixtures. They do not establish expected accuracy, false-positive rate, or attack coverage for another application.

### Metrics

```bash
cargo run --example metrics_monitoring
```

[`metrics_monitoring.rs`](../examples/metrics_monitoring.rs) demonstrates process-local detector counters and timing observations. It intentionally runs timed loops and takes longer than the basic examples. Its alert thresholds are illustrative, not service-level recommendations.

## Integration Examples

### Ollama

[`ollama_integration.rs`](../examples/ollama_integration.rs) demonstrates placing an explicit decision before an HTTP call to a local Ollama server.

Prerequisites:

1. Install and start Ollama separately.
2. Make its API available at `http://localhost:11434`.
3. Ensure the example's configured model exists locally.
4. Review the code before exposing any listener or model to untrusted traffic.

Run:

```bash
cargo run --example ollama_integration
```

This is an illustrative client flow, not a hardened gateway. Add authentication, authorization, request limits, TLS/network policy, output/tool validation, and privacy controls in a real service.

### Async Processing

```bash
cargo run --example async_processing
```

[`async_processing.rs`](../examples/async_processing.rs) compares sequential and concurrent calls over an embedded input set. Its wall-clock output depends on the machine, build profile, scheduler, and fixture set; use `cargo bench` and a representative workload for performance decisions.

### Policy and Response Handling

```bash
cargo run --example policy_enforcement
cargo run --example validate_responses
```

These examples show application-level branching and running the text detector against different input classes. FluxPrompt does not automatically intercept model responses; an application must pass response text to `analyze` explicitly. Detection of a response string is still heuristic and does not replace schema, content, or tool validation.

[`response_validation.rs`](../examples/response_validation.rs) is interactive and reads from standard input:

```bash
cargo run --example response_validation
```

## Broader Demonstration

[`complete_demo.rs`](../examples/complete_demo.rs) exercises a larger portion of the public API with embedded prompts:

```bash
cargo run --example complete_demo
```

Treat any rates or timing printed by a demonstration as fixture outcomes, not general detector efficacy or a performance benchmark.

## Before Copying an Example

- Replace fixture policy with your own threat model and evaluation set.
- Validate configuration before constructing or updating a detector.
- Pin the FluxPrompt Git revision.
- Remove raw prompt logging and demo output.
- Add service-level request, concurrency, and rate limits.
- Keep tools least-privileged and validate every consequential action.
- Turn examples into tests for the behavior your application depends on.
