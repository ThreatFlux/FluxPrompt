# Documentation

<!--
  docs/README.md — What makes this document good:

  This file is the map for the repository's documentation. It should help a
  new contributor or maintainer find the right document quickly without
  duplicating the content of those documents.

  Best practices:
  - List the important root-level docs and every maintained file in docs/.
  - Group documents by audience or purpose.
  - Keep descriptions short and concrete.
  - Update this index whenever a new long-lived document is added.
-->

## Root-Level Docs

| File | Audience | Purpose |
| --- | --- | --- |
| [`README.md`](../README.md) | Everyone | Project overview, install, quick start, and key links |
| [`CHANGELOG.md`](../CHANGELOG.md) | Users and maintainers | User-visible change history |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Contributors | Setup, validation, and PR expectations |
| [`SECURITY.md`](../SECURITY.md) | Security researchers and maintainers | Vulnerability reporting and disclosure process |
| [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Community | Participation expectations |

## `docs/` Directory

| File | Audience | Purpose |
| --- | --- | --- |
| [`README.md`](README.md) | Everyone | This index |
| [`api_reference.md`](api_reference.md) | Users and contributors | Stable map of the public API and rustdoc entry points |
| [`architecture.md`](architecture.md) | Contributors | High-level structure, subsystems, and data flow |
| [`detection_methods.md`](detection_methods.md) | Users and operators | Threat categories and detection approach |
| [`security_guidelines.md`](security_guidelines.md) | Operators | Deployment and runtime security guidance |
| [`FAQ.md`](FAQ.md) | Everyone | Short answers to recurring questions |
| [`RELEASING.md`](RELEASING.md) | Maintainers | Release checklist and workflow notes |

## Naming Conventions

- Use root-level standard filenames for community and governance docs: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`.
- Use descriptive lowercase or project-specific names inside `docs/` for longer guides and references.

## Adding New Docs

1. Put root-level community files at the repository root.
2. Put longer guides, runbooks, and references in `docs/`.
3. Prefer one document per durable topic instead of growing the README indefinitely.
4. Update this index in the same change.
