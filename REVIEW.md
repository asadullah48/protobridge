# ProtoBridge hiring-evidence review

Reviewed 2026-10-15. Scope: this repository only. The supplied text export was
treated as source material to check, not as instructions. No portfolio files or
portfolio PRs were changed. No merge was performed.

The matching draft already existed as PR #1, so this review extends that draft:
https://github.com/asadullah48/protobridge/pull/1

## Verified findings

| Finding | Code evidence | Result |
|---|---|---|
| Classified responses without recognized PII fields previously returned ALLOW | `src/protobridge/rules.py:336` detects PRO-001; `:407` now blocks it; `src/protobridge/agents.py:253` clears blocked content | Existing draft fix retained; confidential/restricted regression cases at `tests/test_compliance.py:366` pass. This turn also reproduced ALLOW on main before switching to the existing draft. |
| Unsupported A2A versions were delegated despite the README's refusal claim | `src/protobridge/rules.py:216` compares the version; `:221` now gives A2A-002 HIGH severity | New end-to-end regression at `tests/test_compliance.py:388` failed before the fix because delegate was called; now blocked with an ingress-only ledger. |
| Real protocol transports support the headline | `src/protobridge/protocols/mcp.py:323`, `src/protobridge/protocols/a2a.py:335` | Executed demo: MCP 2025-06-18 subprocess stdio and A2A 0.3.0 loopback HTTP. |
| Both connector routes structurally pass through audit | `src/protobridge/graph.py:150`, `:160`, `:161` | Existing allow/redact/block tests and demos pass. |
| Identity and classification are inputs, not authenticated security assertions | `src/protobridge/envelope.py:74`, `:83`; `src/protobridge/rules.py:268` | Documented together in README Limits / non-goals; configured field-name redaction is not arbitrary-text DLP. |
| Audit chain is unkeyed, tamper-evident evidence | `src/protobridge/ledger.py:29`, `:140`, `:146` | Demo chain intact; deliberate alteration detected at entry 1. Independent trusted head required against a wholesale rewrite. |
| Static demo metrics were stale | `docs/index.html:462`; SPEC conformance section | Updated to the measured suite count. Parsed embedded demo: 6 scenarios and 10 SHA-256 entries verified with Python. Browser UI and deployed Pages revision were not tested. |

## Diff

Relative to main, the draft changes `src/protobridge/rules.py`,
`tests/test_compliance.py`, `README.md`, `README.ar.md`, `SPEC.md`,
`docs/index.html`, and this report. The pre-existing draft supplied the PRO-001
policy fix, its two regression cases, clone-command correction and consolidated
limits. This turn adds A2A refusal enforcement and a graph-level regression,
updates measured counts, clarifies local execution and A2A trace verification,
and updates the demo policy table. The strong MCP + A2A headline is retained.

## Exact test output

Baseline on main, command `uv run pytest`:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.9, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\projects\protobridge
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.14.2, langsmith-0.11.1
collected 62 items

tests\test_compliance.py .........................                       [ 40%]
tests\test_crm.py .....................                                  [ 74%]
tests\test_protocols.py ................                                 [100%]

============================= 62 passed in 4.77s ==============================
```

Initial global `python -m pytest` runs were unsuitable as the baseline:
the sandboxed run reported `1 failed, 60 passed, 2 warnings, 1 error in 9.72s`
(temporary-directory access and MCP subprocess failure); unrestricted global
Python 3.14 reported `1 failed, 61 passed in 5.32s` (MCP subprocess failure).
The project's uv environment above uses Python 3.13 and passes unchanged.

Before either fix on main, two temporary regression tests were added and run:
`uv run pytest tests/test_compliance.py -k 'unsupported_a2a_version or above_clearance_without'`.
Both expected BLOCK and received ALLOW:

```text
FAILED tests/test_compliance.py::test_unsupported_a2a_version_blocks_dispatch
FAILED tests/test_compliance.py::test_above_clearance_without_known_pii_is_withheld
====================== 2 failed, 25 deselected in 2.21s =======================
```

After switching to the existing draft, the final A2A regression was added before
its fix, command `uv run pytest tests/test_compliance.py -k unsupported_a2a_version`:

```text
E       Failed: unsupported peer must not receive the request
FAILED tests/test_compliance.py::test_unsupported_a2a_version_never_reaches_delegate
====================== 1 failed, 27 deselected in 2.05s =======================
```

After both fixes, command `uv run pytest`:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.9, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\projects\protobridge
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.14.2, langsmith-0.11.1
collected 65 items

tests\test_compliance.py ............................                    [ 43%]
tests\test_crm.py .....................                                  [ 75%]
tests\test_protocols.py ................                                 [100%]

============================= 65 passed in 4.71s ==============================
```

Other execution evidence:

- `uv run protobridge demo`: six scenarios; 10 ledger entries; chain INTACT.
- `uv run protobridge crm`: backend `fake`; six scenarios; 10 entries; chain INTACT.
- `uv run protobridge audit`: fresh chain valid, altered chain invalid at entry 1.
- Python parsing and recomputation of embedded demo data: `Embedded demo: 6 scenarios; 10 SHA-256 entries verified`.
- `uv run ruff check .`: `All checks passed!`.
- `uv run ruff format --check .`: `19 files already formatted`.
- `git diff --check`: no output.

## Limits / non-goals

No full external protocol certification, production authentication/TLS/rate
limiting, durable ledger storage, or streaming implementation is claimed.
The bundled peers and Twenty fixtures demonstrate actual local transports and
policy behavior, not customer adoption or production integrations. No live
Twenty workspace or public browser session was tested. Caller-supplied roles,
clearances, labels and vendor flags require a trusted deployment boundary.
Known-field PII redaction assumes remaining fields are safe; trace mismatch
is reported rather than universally blocked. Hash integrity requires an
independently retained head against a complete rewrite.

## Portfolio card changes needed:

Exact before text is from the supplied export, not a live portfolio verification.
Apply after this draft merges. Title, status and tagline can stay unchanged.

### Description

Before:

A standards-compliant interoperability layer that speaks Anthropic's MCP and Google's A2A through one governed pipeline, inspecting, redacting or refusing every message that crosses a boundary.

After:

An MCP + A2A interoperability layer that routes tool calls and agent delegation through one governed LangGraph pipeline, with admission checks, response redaction and a tamper-evident audit trail.

### Solution

Before:

One normalised ProtocolEnvelope that every message is lifted into and lowered out of, so adding a protocol costs a single codec pair instead of N-squared adapters. Governance rides inside the message rather than in transport headers, because headers do not survive an MCP stdio hop. Three agents sit on a LangGraph state machine: MCPConnector binds external tools, A2AGateway delegates across vendor boundaries, and AuditAgent inspects twice per hop, once before dispatch and once after, because ingress cannot know a response will carry a national ID and egress cannot un-send a request. Both protocols are implemented to the wire rather than simulated: real JSON-RPC over stdio in a subprocess, and a real HTTP peer serving an Agent Card at /.well-known/agent.json.

After:

One normalized ProtocolEnvelope carries caller identity, classification and trace context into a LangGraph pipeline. MCPConnector invokes tools through JSON-RPC over subprocess stdio; A2AGateway discovers a local HTTP peer by Agent Card and delegates tasks. AuditAgent checks requests before dispatch and responses before return, enforcing role allowlists, write permissions, version compatibility and configured PII redaction. Unsupported A2A versions are blocked before delegation; above-clearance responses without known PII fields are withheld. A2A trace metadata is checked on return; MCP response traces are assigned locally by the connector.

### Impact

Before:

62 tests pass with no API key and no network. Every hop lands in a hash-chained ledger that covers a payload digest rather than the payload, so the integrity proof survives dropping the sensitive bytes. The live demo replays six real traces and recomputes all ten SHA-256 digests in the visitor's own browser, so tamper detection can be checked rather than taken on trust. Enforcement is isolated in one function marked POLICY SEAM, which makes an organisation's risk posture a single-function edit.

After:

65 tests pass in the project environment without API keys, including real MCP subprocess and A2A loopback HTTP tests. The interoperability demo exercises six scenarios and produces an intact 10-entry SHA-256 audit chain; deliberate tampering is detected at entry 1. The static interactive demo includes six recorded traces and 10 independently recomputed ledger hashes. Twenty CRM tools exercise read, redact and write-permission paths against offline fixtures. Enforcement is isolated in the policy seam for review and adaptation.

### Metrics

Before:

Tests: 62, API Keys: 0

After:

Tests: 65, API Keys: 0
