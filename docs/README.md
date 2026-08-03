# FluxPrompt Documentation

Use this page to find the shortest path for your task. Item-level Rust API documentation is generated from the crate source with `cargo doc --no-deps`.

## Use FluxPrompt

| Guide | Use it when you need to |
| --- | --- |
| [Configuration](configuration.md) | Install from crates.io, choose a constructor, tune detection, or load JSON/YAML |
| [API reference](api_reference.md) | Find the main public types and understand result/mitigation semantics |
| [Examples](examples.md) | Choose a runnable example and understand its prerequisites |
| [FAQ](FAQ.md) | Resolve common integration and behavior questions quickly |

## Understand and Operate It

| Guide | Use it when you need to |
| --- | --- |
| [Threat model](threat-model.md) | Decide whether FluxPrompt addresses your risk and understand its limitations |
| [Detection methods](detection_methods.md) | Understand the implemented analysis pipeline and scoring inputs |
| [Security guidelines](security_guidelines.md) | Add enforcement, observability, privacy controls, and defense in depth |
| [Architecture](architecture.md) | Work on the crate or understand component boundaries and state |

## Contribute and Release

| Document | Purpose |
| --- | --- |
| [Contributing](../CONTRIBUTING.md) | Development setup, checks, and pull request expectations |
| [Security policy](../SECURITY.md) | Private vulnerability and bypass reporting |
| [Changelog](../CHANGELOG.md) | Released and pending user-visible changes |
| [Releasing](RELEASING.md) | Maintainer release checklist and current automation behavior |
| [Code of conduct](../CODE_OF_CONDUCT.md) | Community participation expectations |

## Documentation Rules

- Describe behavior present in the current source; link future work to an issue instead of documenting it as implemented.
- Compile copied Rust examples or derive them from an example target.
- Treat fixture results as test observations, not security efficacy or performance guarantees.
- Update the threat model when a detector, trust boundary, or enforcement responsibility changes.
- Add every durable document in `docs/` to this index.
