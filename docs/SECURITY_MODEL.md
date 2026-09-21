# Security model

The target is hostile input. DriftSeal never installs a scanned dependency, imports its code, executes a target binary, follows skill instructions, or invokes MCP tools.

| Boundary | Control |
|---|---|
| Network | HTTPS/443 only, no URL credentials, all DNS answers public, pinned-IP connection with hostname-verified TLS |
| Redirects | GET max 2, POST zero, expected registry host allowlists |
| Artifact | 12 MiB download, 32 MiB expansion, 1,500 entries, 1 MiB/member, compression-ratio limit |
| Archive paths | No traversal, absolute paths, links, devices, sparse files, duplicate members or encryption |
| Parsing | Temporary-directory cleanup; no recursive archives; JSON depth 40, nodes 30,000, size 1 MiB |
| Process | Own-code subprocess, 45-second wall timeout, 35-second CPU, 384 MiB Linux address space, 64 open files |
| API | Request bounds, persistent rate limits, queue limits, exact-origin CSRF, HTTP-only secure production cookies |
| Data | Parameterized SQL, per-workspace authorization, private reports, opt-in status-only public badges |
| Billing | Official raw-body signature validation, five-minute replay window, unique event IDs, current-state reconciliation |
| Alerts | Public-IP-pinned HTTPS, no redirects, encrypted signing secrets, HMAC, event IDs, five attempts, persistent log |
| Web | Escaped templates and DOM evidence, no package Markdown/SVG rendering, restrictive CSP and security headers |

Residual risks: deterministic string rules are not semantic program analysis. Documentation/dead-code references may produce capability indicators. Dynamic schemas, runtime behavior, authenticated/stateful MCP sessions, YAML structure, binary contents and transitive resolution are outside coverage. Direct npm/PyPI vulnerability lookups may fail; reports state the gap.

Approved-baseline comparison and previous-observation capability reduction are distinct. An unchanged artifact may still be malicious; changed bytes may be harmless. Cosmetic whitespace in descriptions is normalized. Artifact changes remain informational even when the normalized tool surface is unchanged.

Framework mappings use public identifiers only: CWE-78, CWE-506, CWE-532, CWE-829 and CWE-1427. References are not endorsements or claims of compliance. Other framework mappings are intentionally omitted until their exact versions and licensing can be verified.

Private local scanning uploads nothing. Cloud input is encrypted in the transient queue, cleared at completion/failure, and anonymous reports expire after 24 hours. Hosted approved baselines and event-linked evidence survive scan-history pruning. Event suppression never deletes historical evidence.

