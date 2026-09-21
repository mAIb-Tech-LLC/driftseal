# Contributing

Keep contributions focused on deterministic trust drift: artifact identities, tool contracts, capability changes and evidence quality. Do not add target execution, a generic scanner suite or LLM-dependent detection.

Every rule change needs benign and risky fixtures. Each new drift rule must include old/new values, a path, severity, confidence, rationale and remediation. Do not copy proprietary rule text. Use framework identifiers with public references.

Run `python -m pytest -q` and `ruff check driftseal tests scripts` before submitting. Keep dependencies locked for the Linux deployment target. Never add credentials, raw private repositories or real credential fixtures. Use synthetic values.

Public contributions apply to the Apache-2.0 components listed in LICENSE. Hosted code is not part of the public distribution.

