# Security Policy

## Supported Versions

FluxPrompt is an early-stage project. Security fixes are made on the `main` branch and, when maintainers publish a release, in a new release. Older tags may not receive backports.

The crate is not currently published on crates.io. GitHub tags and repository commits are the authoritative public source versions.

## Report Privately

Do not open a public issue, discussion, or pull request for a suspected vulnerability or a working detector bypass with security impact.

Use one of these private channels:

1. [GitHub private vulnerability reporting](https://github.com/ThreatFlux/FluxPrompt/security/advisories/new), when available.
2. Email `security@threatflux.ai` if private reporting is unavailable or unsuitable.

If email transport does not meet your confidentiality needs, send a minimal request for a secure channel before sharing exploit details. Do not send secrets, customer data, credentials, or unnecessary prompt contents.

## What to Include

Provide enough information to reproduce and assess the report:

- FluxPrompt tag or full commit SHA;
- Rust version, target, enabled Cargo features, and relevant configuration;
- affected component or API;
- minimal input and reproduction steps;
- observed and expected behavior;
- realistic security impact and required attacker access;
- known workarounds or compensating controls;
- whether and where the issue has already been disclosed.

For a prompt-injection bypass, include the application trust boundary and consequence. A phrase that the detector does not flag is not automatically a vulnerability: explain how the miss defeats a documented expectation or contributes to unauthorized data access, tool use, policy bypass, denial of service, or another concrete impact.

## Relevant Report Classes

Examples that may be security-relevant include:

- bypasses that contradict the documented threat model and have concrete impact;
- panics, excessive resource use, or malformed-input behavior reachable by untrusted input;
- unsafe sanitization or span/normalization behavior that causes a policy failure;
- configuration validation or enforcement behavior that creates a security boundary bypass;
- leakage of prompt text, credentials, or sensitive configuration through library behavior;
- dependency or release-integrity issues specific to this repository.

Ordinary false positives, documentation gaps, feature requests, and misses without a demonstrated security consequence can be reported as public bugs after removing sensitive details.

## What Happens Next

Maintainers will assess reproducibility, affected versions, impact, and whether the report belongs in the library or the integrating application. Response and remediation time depends on severity, complexity, maintainer availability, and release coordination; this policy does not promise a service-level response time.

When appropriate, maintainers may coordinate a fix, tests, a release, and a GitHub security advisory. Please allow time for users to receive a mitigation before publishing working exploit details.

## Disclosure

Coordinate public disclosure with the maintainers. Once a fix or mitigation is available, the project may publish an advisory or changelog entry describing affected versions, impact, and remediation without exposing unnecessary user data.

## Security Model

Prompt-injection detection has inherent false positives and false negatives. FluxPrompt is not a security boundary and does not guarantee that input is safe. Review [docs/threat-model.md](docs/threat-model.md) for supported signals, limitations, and host-application responsibilities.
