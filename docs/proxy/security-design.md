# AI Egress Proxy — Security Design

> **Document status**: Living design document. Regenerated from source code and the
> 8-section outline in `docs/proxy/TODO.md` (branch `claude/ai-proxy-security-HNLsW`,
> last pushed commit `8f04b25`).
>
> **Audience**: Security engineers, backend architects, compliance officers (DPO/CISO),
> and developers integrating the proxy into their development workflow.
>
> **Reading paths**:
> - Developers getting started → §1 → §2 → §7 (Quick start in Appendix B)
> - Security architects → §1 → §4 → §6 → §8 (ADRs)
> - Compliance / DPO / CISO → §1 → §3 → §5 → §4.6 (Audit)
> - Architects evaluating migration → §2 → §7

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State and Capabilities](#2-current-state-and-capabilities)
3. [BA Analysis — PII Masking and Mapping](#3-ba-analysis--pii-masking-and-mapping)
   - 3.1 Stakeholders
   - 3.2 Use Cases US-1..US-8
   - 3.3 Functional Requirements FR-1..FR-12
   - 3.4 Non-Functional Requirements NFR-1..NFR-8
   - 3.5 Data Classification Tiers
   - 3.6 Risk Register R-1..R-10
   - 3.7 Acceptance Criteria AC-1..AC-7
4. [SA Architecture — PII Layer](#4-sa-architecture--pii-layer)
   - 4.1 Layered Detection Pipeline
   - 4.2 Token Vault
   - 4.3 Token Format and the BPE-Paraphrase Problem
   - 4.4 Strategy Mix
   - 4.5 Bypass Workflow
   - 4.6 Audit and Compliance Chain
5. [BA Extension — Source Code DLP](#5-ba-extension--source-code-dlp)
   - 5.1 Use Cases US-9..US-15
   - 5.2 Twelve New Entity Classes
   - 5.3 Functional Requirements FR-13..FR-21
   - 5.4 Risks R-11..R-17
   - 5.5 Compliance: Trade Secret and Unfair Competition Law
6. [SA Extension — Source Code Layer](#6-sa-extension--source-code-layer)
   - 6.1 Four-Lane Detector Architecture
   - 6.2 Token Grammar — Shape-Preserving Substitutions
   - 6.3 SQL Pipeline
   - 6.4 Stack-Trace Handling
   - 6.5 Codename Dictionary Self-Service
   - 6.6 Defensive Detokenization
   - 6.7 Performance Budget
7. [Migration Plan](#7-migration-plan)
8. [Architecture Decision Records](#8-architecture-decision-records)
- [Appendix A: Follow-up Technical TODOs](#appendix-a-follow-up-technical-todos)
- [Appendix B: Quick Start](#appendix-b-quick-start)
- [Appendix C: Security Review Backlog (pre-P2 blockers)](#appendix-c-security-review-backlog-pre-p2-blockers)

---

## 1. Executive Summary

### Problem Statement

Engineering teams increasingly rely on AI coding assistants to accelerate development. Those assistants need access to real code, real configuration, and real conversations — all of which routinely contain material that must never leave the organisation's trust boundary:

- **Personal identifiable information (PII)**: email addresses, Vietnamese Căn cước công dân (CCCD, 12-digit citizen ID), Mã số thuế (MST, tax code), Bảo hiểm xã hội (BHXH, social insurance number), bank account numbers, phone numbers.
- **Source-code secrets**: API keys, JWT tokens, private key blobs, credentials.
- **Trade-sensitive source identifiers**: internal npm/Maven package names, project codenames, partner names, internal hostnames, proprietary SQL schema names — items that collectively constitute "confidential business information" under Luật Cạnh tranh 2018 Điều 45 and trade secrets under Luật Sở hữu trí tuệ 2005 Điều 84.

Without an interception layer, every prompt sent to a third-party AI API is a potential data-exfiltration event. The AI Egress Proxy (`src/proxy/`) is that interception layer.

### What the Three Commits Shipped

| Commit | SHA | Description |
|--------|-----|-------------|
| PoC | `1eb7045` | Seven TypeScript modules, Anthropic-compatible HTTP proxy, regex DLP (block/redact), tool allowlist, HITL approval, audit log, 41 tests |
| Hardening | `ab9ac90` | 15 review fixes: constant-time bearer auth, SSE rolling-buffer split-secret detection, `realpath` symlink rejection, HITL file-permission check, backpressure, Zod upstream response validation, `fsync` on audit writes, HTTPS-only egress guard, XFF trust flag — tests → 70 |
| P1 vault + dict | `8f04b25` | Reversible tokenisation: `vault.ts` (in-process `InProcessTokenVault`), `dictionary.ts` (Aho-Corasick, zero npm deps), `sample-dictionary.json`, `tokenize` policy in DLP pipeline, `SseDetokenizer` class, system-prompt injection of DLP anchor, full round-trip — tests → 94 |

### What This Document Adds

This document records the business analysis (BA) and solution architecture (SA) that precede and motivate the implementation. It answers four questions the code alone cannot answer:

1. **Who** needs this and what do they need it to do? (§3 BA PII, §5 BA code)
2. **Why** were specific architectural choices made over alternatives? (§8 ADRs)
3. **What** does the planned evolution look like and what are the exit criteria for each phase? (§7 Migration)
4. **Which** legal obligations does the design address? (§3.5, §5.5)

### Phased Roadmap at a Glance

```
P1 (DONE ✅ 8f04b25)  Vault + PII tokenisation + dictionary lane
P2                    Presidio NER sidecar + 4 code classes + self-service portal
P2.5                  AST lane (tree-sitter + node-sql-parser) behind feature flag
P3                    Bypass JWT workflow + KMS + multi-tenant vault isolation
```

---

## 2. Current State and Capabilities

### 2.1 Module Inventory

All proxy source lives under `src/proxy/`. The table below maps each module to its primary responsibility.

| File | Lines | Role |
|------|-------|------|
| `config.ts` | 310 | JSONC loader, Zod schema, `ProxyConfigSchema`, env overrides, `compileConfigPatterns` with ReDoS guard |
| `dlp.ts` | 1117 | Core DLP engine: `scan`, `applyPolicy`, `walkAndRedact`, `redactAnthropicRequest`, `SseRedactor`, `SseDetokenizer`, `detokenize`, `injectDlpInstruction` |
| `vault.ts` | 121 | `TokenVault` interface + `InProcessTokenVault` (NFC/case-fold keying, TTL, per-conv isolation) + `TOKEN_REGEX` |
| `dictionary.ts` | 213 | `Dictionary` class backed by Aho-Corasick automaton, word-boundary checks, longest-leftmost-wins dedup |
| `allowlist.ts` | 213 | MCP tool allowlist, URL domain allowlist, SSRF guard integration, `scanRequestForBannedTools` |
| `audit.ts` | 110 | Append-only JSONL audit log, daily rotation, `fsyncSync` per event, no raw sensitive data persisted |
| `agent-loop.ts` | 450 | Multi-turn tool-use loop, HITL approval (file-based, permission-hardened), upstream response Zod validation |
| `server.ts` | 684 | HTTP server (`node:http`), bearer-token auth (constant-time), SSE streaming pipeline (detokenize → redact), backpressure, Prometheus-format `/metrics`, `/health` |
| `cli.ts` | 162 | `commander` CLI (`start`, `audit`, `hitl approve/deny`), graceful shutdown |
| `sample-dictionary.json` | 8 | Six worked dictionary entries used in integration tests |

### 2.2 Configuration Shape

`src/proxy/config.ts:33` defines `ProxyConfigSchema` via Zod. Every field has a safe default; the file is loaded from `~/.config/omc/proxy.jsonc` (JSONC format — comments allowed) with env-var overrides applied second.

```typescript
// Key sections of ProxyConfigSchema (src/proxy/config.ts:33-84)
{
  listen:       { host: "127.0.0.1", port: 11434 },
  upstream:     { baseUrl: "https://api.anthropic.com", apiKeyEnv: "ANTHROPIC_API_KEY" },
  dlp:          { patterns: DlpPattern[], customDenyTerms: string[] },
  allowlist:    { mcpTools: string[], urlDomains: string[], pathPrefixes: string[] },
  hitl:         { enabled: boolean, sensitiveTools: string[], timeoutMs: 60_000 },
  audit:        { dir: "~/.omc/proxy/audit", maxBodyBytes: 1_000_000 },
  agentLoop:    { enabled: boolean, maxIterations: 5, maxToolOutputBytes: 100_000 },
  auth:         { tokenEnv: "OMC_PROXY_CLIENT_TOKEN" },
  vault:        { ttlSeconds: 86400 },
  dictionary:   { path?: string, entries: DictionaryEntryConfig[] },
  conversation: { headerName: "X-OMC-Conversation-Id" },
}
```

Key security properties of the config layer:

- Every regex in `dlp.patterns` is run through `safe-regex` at startup (`src/proxy/config.ts:257-260`). A ReDoS-vulnerable pattern causes a startup error rather than a runtime hang.
- API keys are **never** stored in the config file — only env-var names. `redactConfigSecrets` returns a safe copy for logging.
- Public-interface binding (`0.0.0.0` / `::`) is blocked unless `OMC_PROXY_ALLOW_PUBLIC=1` is set (`src/proxy/server.ts:142-149`).
- `X-Forwarded-For` trust for IP attribution is opt-in via `OMC_PROXY_TRUST_PROXY=1` (`src/proxy/server.ts:80-84`).

### 2.3 DLP Patterns Shipped by Default

`src/proxy/config.ts:97-144` defines nine default patterns:

| Pattern name | Regex summary | Policy |
|---|---|---|
| `email` | RFC-5321-ish local-part + domain | `redact` |
| `phone_intl` | `+<CC> ...` international | `redact` |
| `phone_vn` | Vietnamese mobile `0[35789]\d{8}` | `redact` |
| `jwt` | `eyJ...` three-part base64url | `block` |
| `aws_access_key` | `AKIA\|ASIA` + 16 chars | `block` |
| `private_key` | `-----BEGIN * PRIVATE KEY-----` | `block` |
| `generic_api_key` | `sk-...` 20+ chars | `block` |
| `github_token` | `gh[pousr]_` + 30 chars | `block` |
| `cccd_vn` | 12-digit number `\b\d{12}\b` | `redact` |

> **Note on `cccd_vn`**: The 12-digit regex has a known false-positive rate against 12-digit order IDs and phone numbers without separators. **Thông tư 59/2021/TT-BCA does not define a public check-digit algorithm for CCCD**, so a "Luhn-like checksum" mitigation (previously proposed here) cannot be implemented as specified. The agreed mitigation is a structural validator combining (i) province-code allowlist (63 valid codes from Phụ lục Thông tư 59), (ii) gender-century digit consistency (digit 4 constrains the year range in digits 5–6), (iii) year plausibility window (e.g., 1900–current-year), and (iv) contextual trigger regex (prefix tokens `CCCD|CMND|số định danh|citizen id`). See Appendix C §C-5 for the backlog entry and algorithm sketch.

### 2.4 Dictionary Lane

`src/proxy/sample-dictionary.json` ships six representative entries used in integration tests:

```json
[
  {"term": "@vng/zalo-pay-internal-sdk", "classifier": "INTERNAL_PACKAGE", "policy": "tokenize"},
  {"term": "@acme/billing-core",         "classifier": "INTERNAL_PACKAGE", "policy": "tokenize"},
  {"term": "Project Bluefin",            "classifier": "CODENAME",         "policy": "tokenize"},
  {"term": "Project Redwood",            "classifier": "CODENAME",         "policy": "tokenize"},
  {"term": "Vietcombank",                "classifier": "PARTNER_NAME",     "policy": "tokenize"},
  {"term": "gitlab.company.internal",    "classifier": "INTERNAL_HOST",    "policy": "tokenize"}
]
```

The `Dictionary` class (`src/proxy/dictionary.ts:66`) builds two Aho-Corasick automatons at construction time — one case-sensitive (for `INTERNAL_PACKAGE`) and one case-insensitive (for all other classes). Matching is O(n + matches) over the text length, independent of dictionary size, making it suitable for large (10k+) term sets.

### 2.5 Streaming Pipeline

The SSE streaming path in `src/proxy/server.ts:505-613` chains two stateful processors:

```
upstream SSE chunks
    → SseDetokenizer.push()   (vault lookup: token → original)
    → SseRedactor.push()      (safety scan on inbound; tokenize downgraded to redact)
    → writeWithBackpressure() (drain-await if socket buffer full)
    → client
```

The `SseRedactor` holds a 512-byte tail across chunk boundaries (`HOLD_BACK = 512`, `src/proxy/dlp.ts:488`) so secrets split across two chunks are detected. On `content_block_stop` the tail is flushed through a final scan.

### 2.6 Capability Matrix

| Capability | Shipped (commit) | Notes |
|---|---|---|
| HTTP proxy for Anthropic API | PoC `1eb7045` | `POST /v1/messages`, `GET /health`, `GET /metrics` |
| Bearer-token auth (constant-time) | Hardening `ab9ac90` | `src/proxy/server.ts:87-101` |
| DLP: block credentials | PoC `1eb7045` | JWT, AWS key, private key, GitHub token, `sk-*` |
| DLP: redact PII | PoC `1eb7045` | Email, phone, CCCD-VN |
| DLP: tokenise (reversible) | P1 `8f04b25` | Swap PII for `EMAIL_01` etc.; detokenise on response |
| Dictionary lane (Aho-Corasick) | P1 `8f04b25` | `dictionary.ts`, INTERNAL_PACKAGE, CODENAME, PARTNER_NAME, INTERNAL_HOST |
| SSE rolling-buffer split detection | Hardening `ab9ac90` | 512-byte hold-back |
| SSE detokeniser | P1 `8f04b25` | `SseDetokenizer` class |
| System-prompt DLP anchor injection | P1 `8f04b25` | `injectDlpInstruction` |
| MCP tool allowlist | PoC `1eb7045` | Domain + path prefix + SSRF guard |
| HITL approval | PoC `1eb7045` | File-based, permission-hardened (`0o600`) |
| Audit log (JSONL, daily rotation) | PoC `1eb7045` | `fsync` per event; no raw PII logged |
| Agent loop (multi-turn tool use) | PoC `1eb7045` | Zod-validated upstream responses |
| Prometheus metrics | PoC `1eb7045` | `requests_total`, `blocked_total`, `redacted_total` etc. |
| ReDoS guard on patterns | Hardening `ab9ac90` | `safe-regex` at compile time |
| HTTPS-only egress | Hardening `ab9ac90` | `validateUpstreamUrl` rejects `http://` |
| Backpressure (SSE drain-await) | Hardening `ab9ac90` | `once(res, "drain")` |
| In-process token vault (24h TTL) | P1 `8f04b25` | `InProcessTokenVault` |
| Per-conversation token scope | P1 `8f04b25` | `X-OMC-Conversation-Id` header or SHA-256 derived |
| NFC + case-fold dedup in vault | P1 `8f04b25` | `alice@x.com` and `Alice@X.com` → same token |

### 2.7 Test Coverage

94 tests passing across 8 test files as of `8f04b25`:

| Test file | Tests | What it covers |
|---|---|---|
| `dlp.test.ts` | ~35 | `scan`, `applyPolicy`, `redactAnthropicRequest`, `SseRedactor`, `SseDetokenizer`, split-secret across chunks, tokenise round-trip, system-prompt inject |
| `server.integration.test.ts` | ~28 | Full HTTP proxy: health, metrics, DLP block, DLP redact, SSE streaming, tokenise round-trip, bearer auth, dictionary integration |
| `vault.test.ts` | ~12 | Issue/lookup, per-conv isolation, TTL expiry, NFC normalisation, case-fold |
| `dictionary.test.ts` | ~9 | Aho-Corasick matches, longest-leftmost-wins, word-boundary, case-sensitive INTERNAL_PACKAGE, case-insensitive PARTNER_NAME, reload |
| `allowlist.test.ts` | ~4 | Domain match, path prefix, SSRF, tool scan |
| `audit.test.ts` | ~3 | JSONL append, daily rotation, error-field DLP scan |
| `config.test.ts` | ~2 | Schema parse, safe-regex rejection, env overrides |
| `agent-loop.test.ts` | ~1 | Multi-turn loop, HITL approval, Zod validation |

---

## 3. BA Analysis — PII Masking and Mapping

### 3.1 Stakeholders

**Developer (code author)**
The developer uses an AI coding assistant directly, often pasting real data from logs, Postman captures, or staging databases to get a concrete answer. Their concern is workflow friction: they want the proxy to be transparent when content is safe and to stop only what is genuinely risky. They distrust tools that over-redact and break the assistant's usefulness.

**Security Engineer**
Owns the DLP pattern library, reviews audit logs for policy violations, and advises on which classifiers to add or tighten. Their concern is coverage — ensuring that no PII or credential class can be smuggled out by a novel encoding. They also need operability: the ability to update patterns without restarting every developer's session.

**Data Owner / Data Steward**
Owns specific datasets (HR records, payment data, customer profiles). Needs assurance that developers cannot accidentally paste data from these systems into an AI prompt. Their concern is accountability — they want audit evidence linkable to a specific dataset, not just a generic "email redacted" log line.

**Platform / SRE**
Operates the proxy fleet, monitors latency SLAs, performs upgrades, and responds to incidents. Their concern is availability and observability: they need Prometheus-format metrics (`/metrics` endpoint), structured audit JSONL they can forward to a SIEM, and a proxy that fails safe (i.e., blocks rather than passes on configuration error).

**Auditor (internal / external)**
Reviews evidence that personal data is not being transmitted to third-party processors without lawful basis. Under Nghị định 13/2023/NĐ-CP (Vietnam's Personal Data Protection Decree), the organisation must demonstrate that personal data is processed with consent or legitimate interest and that processors are bound by contracts. The auditor needs per-request JSONL evidence showing what was blocked, what was redacted, and when.

**CISO**
Sets the overall policy: which classifiers exist, which are mandatory, what the bypass window is. Their concern is risk posture — specifically whether a threat actor who compromises a developer workstation can exfiltrate source code or PII through the AI channel. They require the system to fail closed: if the proxy is not reachable, Claude Code should not fall back to direct API access.

**DPO (Data Protection Officer)**
Bears legal accountability under NĐ 13/2023 for any data subject's personal data that flows to Anthropic (a foreign processor). Their concern is demonstrating that effective technical controls exist — specifically a proof-of-non-egress audit trail for CCCD numbers, phone numbers, bank account numbers, and any other data categories subject to Vietnamese data localisation requirements. The DPO also needs a formal data impact assessment supported by the risk register in §3.6.

### 3.2 Use Cases US-1 to US-8

| ID | Title | Actor | Precondition | Main Flow | Success Outcome | Compliance Tie-in |
|---|---|---|---|---|---|---|
| US-1 | Refactor PII-safe | Developer | Developer pastes code containing `user.email` and a realistic test email address | Proxy detects email → issues `EMAIL_01` token → sends tokenised prompt → model returns code using `EMAIL_01` → detokenise on response | Developer receives refactored code; real email never left the proxy | NĐ 13/2023 Art. 6 (data minimisation) |
| US-2 | Round-trip persona | Developer | Developer uses a customer name and phone across a multi-turn conversation | Vault maps `Nguyễn Văn A` → `PERSON_01`, `+84 90 111 2222` → `PHONE_01`; both survive across message turns | Conversation coherent; model refers to `PERSON_01` throughout; detokenise restores names on every response | NĐ 13/2023 Art. 6 |
| US-3 | Quarterly egress review | Auditor | Auditor queries daily JSONL audit files for a calendar quarter | Auditor runs `cli.ts audit --from 2026-01-01 --to 2026-03-31`; receives list of events with `dlpMatches` field showing classifier + count | Summary shows zero `cccd_vn` matches escaped (blocked or tokenised); auditor signs off | NĐ 13/2023 Art. 28 (data processor obligations) |
| US-4 | Declarative sensitivity | Security Engineer | Engineer needs to add a new PII class for passport numbers | Engineer edits `proxy.jsonc`, adds a pattern with name `passport_vn`, policy `redact`; restarts proxy | Pattern compiles (ReDoS check passes); proxy redacts passport numbers on first request | Internal policy |
| US-5 | CCCD proof-of-non-egress | DPO | Regulator asks for evidence that citizen IDs are not sent to foreign AI processors | DPO retrieves JSONL for the period; each request either shows `cccd_vn` in `dlpMatches` with policy `redact`/`tokenize`, or the original text contained no match | Audit trail demonstrates technical control; DPO provides to regulator | NĐ 13/2023 Art. 22 (cross-border data transfer prohibition without conditions) |
| US-6 | Codename protection | Developer | Developer pastes code mentioning `Project Bluefin` (an unreleased product codename) | Dictionary lane matches `Project Bluefin` → issues `CODENAME_01` token | AI response uses `CODENAME_01`; partner or competitor cannot infer product roadmap from API logs | Luật SHTT 2005 Điều 84 (trade secret) |
| US-7 | Approved bypass | Developer (with CISO approval) | Developer legitimately needs the AI to reason about a real customer email in a support ticket; has CISO sign-off | Developer triggers bypass workflow; JWT scoped to one conversation is issued; proxy skips tokenisation for that conversation | Developer gets unfiltered AI output for one 15-minute window; bypass event logged | Internal policy; audit evidence for exception handling |
| US-8 | Audit-only canary | Security Engineer | Engineer wants to add a pattern that logs but does not block or redact, to measure prevalence before enforcing | Engineer adds pattern with custom policy `redact` and replacement `[AUDIT:ssn_candidate]` | Pattern fires on matches; audit log shows count; original text passes through with the replacement | Internal policy |

### 3.3 Functional Requirements FR-1 to FR-12

| ID | Statement | Priority | Measurable Acceptance Criterion |
|---|---|---|---|
| FR-1 | The proxy MUST intercept every outbound request to the Anthropic API and apply DLP before forwarding | P0 | `server.integration.test.ts`: all 94 tests pass; no path bypasses DLP |
| FR-2 | The proxy MUST support three DLP policies: `block` (reject request), `redact` (replace with static string), `tokenize` (replace with reversible vault token) | P0 | `dlp.test.ts` covers all three policies including mixed multi-pattern requests |
| FR-3 | Tokenisation MUST be reversible within the same conversation: a token issued on turn N MUST be detokenised to the original value on the response to turn N | P0 | Vault round-trip tests in `dlp.test.ts` and `server.integration.test.ts` |
| FR-4 | Token scope MUST be per-conversation; the same value in two different conversations MUST produce independent tokens | P0 | `vault.test.ts`: "different conv gets an independent token space" |
| FR-5 | The proxy MUST apply Zod validation to all upstream API responses before forwarding them to clients | P1 | `agent-loop.ts`: `parseUpstreamResponse` called on every upstream response |
| FR-6 | Audit events MUST be written to an append-only JSONL file, fsynced per event, rotated daily, and MUST NOT contain raw sensitive text | P0 | `audit.test.ts`; `audit.ts:88-90` DLP-scans error strings before persisting |
| FR-7 | The proxy MUST support a dictionary lane for exact-match identifiers (package names, codenames, partner names, internal hostnames) backed by an Aho-Corasick automaton | P1 | `dictionary.test.ts`: all 9 tests pass |
| FR-8 | The DLP pipeline MUST detect secrets split across SSE chunk boundaries using a rolling buffer of at least 512 bytes | P1 | `dlp.test.ts`: split-secret SSE tests |
| FR-9 | The system MUST inject a system-prompt DLP anchor instruction whenever tokenisation is active, so the model does not paraphrase tokens | P1 | `dlp.ts:311-333` `injectDlpInstruction`; tested in `dlp.test.ts` |
| FR-10 | All DLP regex patterns MUST be validated against `safe-regex` at startup to prevent ReDoS | P1 | `config.ts:257-260`; `config.test.ts` |
| FR-11 | The proxy MUST support human-in-the-loop (HITL) approval for sensitive tool calls | P2 | `agent-loop.ts`: `waitForHitlDecision`; file permissions enforced (`0o600`) |
| FR-12 | The proxy MUST expose Prometheus-format counters at `GET /metrics` for `requests_total`, `blocked_total`, `redacted_total`, `tool_calls_total`, `hitl_pending`, `errors_total` | P1 | `server.ts:261-284`; tested in `server.integration.test.ts` |

### 3.4 Non-Functional Requirements NFR-1 to NFR-8

| ID | Statement | Priority | Measurable Acceptance |
|---|---|---|---|
| NFR-1 | End-to-end proxy latency (DLP overhead) MUST be ≤ 130ms at p95, measured excluding upstream API latency | P1 | Benchmark: 10k synthetic requests, 95th percentile ≤ 130ms |
| NFR-2 | The proxy MUST bind to `127.0.0.1` by default and MUST refuse to bind to `0.0.0.0` or `::` without an explicit opt-in env var | P0 | `server.ts:142-149`; verified in integration test |
| NFR-3 | All upstream communication MUST use HTTPS. The proxy MUST reject any configured upstream URL that uses the `http://` scheme (except `OMC_PROXY_ALLOW_HTTP_UPSTREAM=1` for test environments) | P0 | `allowlist.ts:validateUpstreamUrl`; test env uses flag |
| NFR-4 | Bearer-token comparison MUST be constant-time to prevent timing attacks that reveal token length or prefix | P0 | `server.ts:87-101` `constantTimeTokenMatch` using `crypto.timingSafeEqual` |
| NFR-5 | The system MUST handle back-pressure on SSE streaming: if the client socket buffer is full, the proxy MUST pause reading from upstream until the buffer drains | P1 | `server.ts:536-543` `writeWithBackpressure` using `once(res, "drain")` |
| NFR-6 | Token vault entries MUST expire after a configurable TTL (default 24 hours). The `purgeExpired()` method MUST be callable on a schedule to avoid unbounded memory growth | P1 | `vault.ts:110-117`; TTL expiry test in `vault.test.ts` |
| NFR-7 | The audit log format MUST be stable JSON Lines (one JSON object per line) with fields `ts`, `reqId`, `clientIp`, `phase`, `dlpMatches` (classifier + count only, no raw values) | P0 | `audit.ts:34-48` `AuditEvent` interface |
| NFR-8 | The proxy MUST fail closed: if the upstream API key is not configured, the proxy MUST return 503 rather than forwarding the request unauthenticated | P0 | `server.ts:290-306` |

### 3.5 Data Classification Tiers

The proxy enforces four classification tiers. The tier determines the default policy when a match is found.

#### Tier 1: PUBLIC

Data that can be disclosed without harm. The proxy ignores this tier — no patterns fire.

*Example*: A public GitHub username, a company's public website URL.

#### Tier 2: INTERNAL

Data that should not leave the organisation but whose disclosure carries limited direct harm. Default policy: **redact** (replace with static placeholder).

*Example*: Internal Slack channel names, internal wiki page titles, first-party employee email addresses on `@company.vn` domain.

**Worked example**:

```
Input:  "Discuss the approach with team@engineering.vng.vn before Friday"
Output: "Discuss the approach with [REDACTED:email] before Friday"
```

#### Tier 3: CONFIDENTIAL

Data whose disclosure could harm individuals or the organisation. Requires **tokenise** policy so the AI model can reason about the data structurally without seeing real values, and the developer receives real values in the response.

| Data Category | Vietnamese Name / Code | Example | Detection |
|---|---|---|---|
| Citizen ID | Căn cước công dân (CCCD) | `012345678901` (12 digits) | Regex `\b\d{12}\b` |
| Tax Code | Mã số thuế (MST) | `0316823497` (10 digits, enterprise), `0316823497-001` (branch) | Regex (planned) |
| Social Insurance | Bảo hiểm xã hội (BHXH) | `7901234567` (10 digits) | Regex (planned) |
| Vietnamese mobile phone | — | `0901234567` | Regex `\b0[35789]\d{8}\b` |
| International phone | — | `+84 90 123 4567` | Regex `\+\d{1,3}...` |

**Worked example (CCCD)**:

```
Input:  "Customer CCCD is 012345678901, verify before proceeding"
Output: "Customer CCCD is CCCD_VN_01, verify before proceeding"
Vault:  conv:abc123 → CCCD_VN_01 → "012345678901"
Model response: "CCCD_VN_01 has been verified"
Detokenised: "012345678901 has been verified"
```

#### Tier 4: RESTRICTED

Data whose disclosure is an immediate regulatory breach or a security incident. Policy: **block** (reject the entire request, return 400). No tokenisation is attempted.

| Data Category | Example | Detection |
|---|---|---|
| API credentials / bearer tokens | `sk-ant-api03-...`, AWS `AKIA...` | Regex patterns in `config.ts:115-133` |
| JWT tokens | `eyJhbGc...` three-part | Regex |
| Private key material | `-----BEGIN RSA PRIVATE KEY-----` | Regex |
| Bank account number (raw) | Vietnamese IBAN / domestic 16-digit | Regex (planned) |

**Worked example (JWT)**:

```
Input:  "Can you debug this: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123xyz"
Outcome: 400 DLP_BLOCKED; dlpMatches: [{name: "jwt", policy: "block", count: 1}]
Developer sees: "Request contains sensitive content and was blocked. Matches: jwt"
```

### 3.6 Risk Register R-1 to R-10

| ID | Description | Likelihood | Impact | Mitigation | Residual Risk |
|---|---|---|---|---|---|
| R-1 | **Vault in-process memory loss**: proxy restart or crash loses all in-flight tokens; model response with tokens cannot be detokenised | Medium | Medium | TTL is 24h; most conversations complete within a session; P3 Redis vault eliminates this | Low after P3 |
| R-2 | **CCCD false positives**: 12-digit regex matches order IDs, PO numbers, phone numbers run together | High | Low (over-redaction, not data loss) | Structural validator: province-code allowlist + gender-century digit + year plausibility + contextual trigger regex (Appendix C §C-5). **No public CCCD check-digit algorithm exists in Thông tư 59/2021/TT-BCA** — any "checksum" framing is incorrect. Log match rate for tuning. | Medium (until backlog item resolved) |
| R-3 | **Split-secret evasion**: attacker deliberately inserts whitespace/newlines to split a credential across SSE chunk boundary | Low | High | 512-byte rolling hold-back in `SseRedactor`; final flush on `content_block_stop` | Low |
| R-4 | **Token paraphrase by model**: model receives `EMAIL_01` but responds with a paraphrased synonym like "the first email address" | Medium | Medium | `injectDlpInstruction` prepends explicit "preserve tokens verbatim" anchor; SSE detokeniser uses regex match not NL parsing | Medium (open A/B test — ADR-5) |
| R-5 | **ReDoS via operator-supplied pattern**: operator adds a catastrophically backtracking regex to `proxy.jsonc` | Low | High (proxy hang, DoS) | `safe-regex` rejects the pattern at startup before any requests are served | Very Low |
| R-6 | **Audit log injection**: an upstream API error message contains newlines or JSON that corrupts the JSONL audit file | Low | Medium | Error strings passed through `applyPolicy` DLP before being written; JSON serialised with `JSON.stringify` (no raw concatenation) | Very Low |
| R-7 | **SSRF via tool call**: agent loop invokes a tool with a URL pointing to an internal metadata service | Medium | High | `validateUrlForSSRF` in `allowlist.ts`; domain allowlist enforced on every tool call | Low |
| R-8 | **HITL bypass via symlink**: attacker creates a symlink at the HITL decision file path before approval to redirect the write | Low | High | `ensureHitlDirSecure` in `agent-loop.ts:165-174` uses `realpath` to reject symlinks; directory is `chmod 0700` | Very Low |
| R-9 | **Bearer token length oracle**: timing attack determines how long the expected token is | Low | Medium | `constantTimeTokenMatch` in `server.ts:87-101` uses `crypto.timingSafeEqual`; length mismatch burns time with a dummy comparison | Very Low |
| R-10 | **Conversation-ID collision**: two unrelated users derive the same conversation ID from the SHA-256 of their bearer token + system prompt | Very Low | Medium | SHA-256 provides 128 bits of collision resistance for 16-char ID; birthday probability negligible at expected scale | Very Low |

### 3.7 Acceptance Criteria AC-1 to AC-7

| ID | Criterion | Verification Method | Linked Tests |
|---|---|---|---|
| AC-1 | A request containing a JWT token pattern MUST be blocked with HTTP 400 and `dlp_blocked` error type | Integration test: send JWT in message body; assert 400 response | `server.integration.test.ts` (DLP block test) |
| AC-2 | A request containing an email address with `tokenize` policy MUST result in the email being replaced with `EMAIL_NN` in the upstream payload, and the original email restored in the response | Round-trip integration test | `server.integration.test.ts` (tokenise round-trip); `dlp.test.ts` |
| AC-3 | Two distinct email addresses in the same conversation MUST receive `EMAIL_01` and `EMAIL_02` respectively; the same address MUST always receive the same token within that conversation | Unit test on `InProcessTokenVault` | `vault.test.ts`: "different values get different sequential tokens" |
| AC-4 | A request with `Authorization: Bearer <wrong-token>` MUST receive HTTP 401 | Integration test | `server.integration.test.ts` (auth test) |
| AC-5 | The audit log for a request containing a CCCD number MUST show `{name: "cccd_vn", policy: "redact", count: 1}` in `dlpMatches` and MUST NOT contain the raw 12-digit number | Grep audit JSONL; assert no 12-digit strings | `audit.test.ts` |
| AC-6 | A dictionary entry for `Vietcombank` (PARTNER_NAME) MUST match `vietcombank` and `VIETCOMBANK` in text but MUST NOT match `Vietcombanking` | Unit test on `Dictionary` | `dictionary.test.ts`: word-boundary and case-insensitive tests |
| AC-7 | A secret split across two SSE chunks (e.g., `sk-ant-` in chunk 1 and `api03-xyz...` in chunk 2) MUST be blocked by `SseRedactor`, not passed through | SSE split-secret test in `dlp.test.ts` | `dlp.test.ts` SSE split tests |

---

## 4. SA Architecture — PII Layer

### 4.1 Layered Detection Pipeline

The detection pipeline is ordered by computational cost. Cheaper, higher-coverage layers run first; expensive layers (NER) run only when regex and dictionary pass.

```mermaid
flowchart TD
    A[Incoming request body\nAnthropicRequestBody JSON] --> B[Regex layer\ncompileConfigPatterns]
    B -->|block match| C[Reject 400]
    B -->|redact/tokenize matches| D[Dictionary layer\nAho-Corasick scan]
    D -->|block match| C
    D -->|redact/tokenize matches| E{NER sidecar\nPlanned P2}
    E -->|block match| C
    E -->|additional matches| F[Merge & deduplicate\nactions list\nlongest-leftmost wins]
    B -->|no match| D
    D -->|no match| E
    E -->|no match| F
    F --> G[Apply policy\napplyPolicy]
    G -->|tokenize| H[vault.issue\nEMAIL_01 etc.]
    G -->|redact| I[static replacement]
    H --> J[injectDlpInstruction\nsystem-prompt anchor]
    I --> J
    J --> K[Forward to upstream\nhttps://api.anthropic.com]
    K --> L[SSE stream]
    L --> M[SseDetokenizer\nvault.lookup]
    M --> N[SseRedactor\ninbound safety scan]
    N --> O[writeWithBackpressure\nto client]
```

**Layer 1 — Regex** (`src/proxy/dlp.ts:69-93` `scan`): All compiled patterns are applied globally against every string field in the request body. The `STRUCTURAL_KEYS` set (`src/proxy/dlp.ts:254-263`) exempts type/id/role/model fields from scanning to prevent false positives like a tool named `sk-test-tool` tripping `generic_api_key`. Pattern order is not significant since all matches are collected before actions are applied.

**Layer 2 — Dictionary** (`src/proxy/dictionary.ts:103-115` `Dictionary.scan`): Runs the Aho-Corasick automaton over the text in one O(n) pass. Two automatons are maintained: one case-sensitive (for `INTERNAL_PACKAGE`) and one case-insensitive (for all other classes). Word-boundary checks prevent `Vietcombank` matching inside `Vietcombanking`. Longest-leftmost-wins dedup ensures non-overlapping output.

**Layer 3 — NER sidecar** (planned P2, §7): A self-hosted Presidio instance augmented with a Vietnamese NER model (`underthesea` or similar). This layer handles entities that are contextually PII but structurally ambiguous: Vietnamese personal names, organisation names, and addresses. The sidecar runs locally to avoid sending data to a cloud NLP endpoint (the exact problem the proxy is solving).

**Merge and action plan** (`src/proxy/dlp.ts:115-194` `applyPolicy`): Regex and dictionary matches are merged into a single action list, sorted by `start` index, ties broken by longest `end` offset. The cursor advances left-to-right; overlapping lower-priority matches are skipped. This ensures a dictionary tokenise of `Project Bluefin` is not split by a regex redact of `Blue`.

### 4.2 Token Vault

#### Current: InProcessTokenVault

```typescript
// src/proxy/vault.ts:15-21
export interface TokenVault {
  issue(convId: string, classifier: string, original: string): string;
  lookup(convId: string, token: string): string | null;
  listTokensForConv(convId: string): string[];
  purge(convId: string): void;
  purgeExpired(): void;
}
```

The `InProcessTokenVault` (`src/proxy/vault.ts:48-118`) stores all mappings in a `Map<string, ConvEntry>` keyed by conversation ID. Each `ConvEntry` holds three maps:

- `originalByToken: Map<string, string>` — token → original (for detokenise)
- `tokenByKey: Map<string, string>` — normalised-key → token (for dedup)
- `counters: Map<string, number>` — classifier → last-issued sequence number

**Key normalisation** (`src/proxy/vault.ts:30-35`): Keys are NFC-normalised (so typographical Unicode equivalents collide) and then case-folded to lowercase — except for `INTERNAL_PACKAGE`, where case sensitivity is preserved because npm package names are case-sensitive. The normalised key format is `"CLASSIFIER lowercased-original"`.

This means `Alice@X.com` and `alice@x.com` issue the same `EMAIL_01` token, reducing vault bloat and preventing two tokens for the same person from confusing the model.

**TTL**: Default 24h (`vault.ttlSeconds: 86400`). `purgeExpired()` is called explicitly; wiring it to `setInterval` in `startProxy` is a tracked TODO (Appendix A).

#### Planned P3: Redis + Envelope Encryption

In production, `InProcessTokenVault` is replaced by `RedisTokenVault` (interface already defined, implementation pending):

```
┌─────────────────────────────────────────────────────────────┐
│  Redis Cluster (data-resident VN datacenter)                │
│                                                              │
│  Key: omc:vault:{convId}:{token}                            │
│  Value: AES-256-GCM encrypted original                      │
│  TTL: vault.ttlSeconds (86400)                              │
│                                                              │
│  DEK (Data Encryption Key): generated per convId, stored   │
│       as omc:dek:{convId}, itself encrypted under KEK       │
│  KEK (Key Encryption Key): rotated monthly, stored in KMS   │
└─────────────────────────────────────────────────────────────┘
```

The interface contract (`TokenVault`) is unchanged. The swap is done by replacing the `new InProcessTokenVault(...)` line in `server.ts:153-155` with `new RedisTokenVault(redisClient, kmsClient, config.vault)`.

**Why Redis?** See ADR-2.

**Why envelope encryption?** A Redis compromise must not expose original PII values. Encrypting values at rest with a per-conversation DEK limits blast radius: an attacker who reads one conversation's DEK can only decrypt that conversation's tokens.

**Vault + detokenise sequence diagram**:

```mermaid
sequenceDiagram
    participant Dev as Developer\n(Claude Code)
    participant Proxy as Proxy\n(server.ts)
    participant Vault as Token Vault
    participant Claude as Anthropic API

    Dev->>Proxy: POST /v1/messages\n{messages: [{text: "review code for alice@vng.vn"}]}
    Proxy->>Proxy: redactAnthropicRequest()\nscan detects email
    Proxy->>Vault: issue(convId, "email", "alice@vng.vn")
    Vault-->>Proxy: "EMAIL_01"
    Proxy->>Proxy: injectDlpInstruction()\nsystem prompt anchor added
    Proxy->>Claude: POST /v1/messages\n{messages: [{text: "review code for EMAIL_01"}]}
    Claude-->>Proxy: SSE: "...EMAIL_01 looks correct..."
    Proxy->>Proxy: SseDetokenizer.push()\nvault.lookup("EMAIL_01")
    Proxy->>Vault: lookup(convId, "EMAIL_01")
    Vault-->>Proxy: "alice@vng.vn"
    Proxy-->>Dev: SSE: "...alice@vng.vn looks correct..."
```

### 4.3 Token Format and the BPE-Paraphrase Problem

#### Token Format

Tokens follow the pattern `CLASSIFIER_NN` where:
- `CLASSIFIER` is the uppercase classifier name (up to ~20 chars)
- `NN` is a zero-padded two-digit sequence number starting at `01`; three digits when count exceeds 99

Examples: `EMAIL_01`, `EMAIL_02`, `PHONE_01`, `CCCD_VN_01`, `CODENAME_01`, `INTERNAL_PACKAGE_01`

The global regex for token detection is:
```typescript
// src/proxy/vault.ts:120
export const TOKEN_REGEX = /\b[A-Z][A-Z0-9_]*_\d{2,3}\b/g;
```

This matches all capitalised underscore-delimited identifiers with a numeric suffix — broad enough to catch all classifier shapes without needing per-classifier patterns.

#### The BPE-Paraphrase Problem

Large language models (including Claude) use byte-pair encoding (BPE) tokenisation internally. When the model encounters a synthetic token like `EMAIL_01`, three failure modes can occur:

1. **Vocabulary collision**: If `EMAIL_01` looks like a meaningful English word or code identifier (it does not, but shorter tokens might), the model may treat it as such and transform it.
2. **Paraphrase instruction following**: The model may rewrite a code comment like "// send to EMAIL_01" as "// send to the first email address" if it infers EMAIL_01 is a placeholder.
3. **Case normalisation**: The model may lowercase `EMAIL_01` to `email_01` in certain output contexts (e.g., inside a JSON string).

**Mitigation — system-prompt anchor** (`src/proxy/dlp.ts:311-333` `injectDlpInstruction`):

```typescript
const DLP_INSTRUCTION =
  "[OMC-DLP]: Preserve identifier tokens of the form EMAIL_NN, PHONE_NN, " +
  "PERSON_NN, PKG_NN, CN_NN, CUSTOMER_NN, HOST_NN, TICKET_NN verbatim. " +
  "Do not rename, paraphrase, or correct typos in these tokens.";
```

This instruction is prepended to the system prompt (or set as the system prompt if none exists) whenever any `tokenize` policy is active. It is idempotent — if `[OMC-DLP]` is already present, re-injection is skipped.

**Remaining risk**: The anchor is advisory, not mechanically enforced. If the model paraphrases despite the anchor, the `SseDetokenizer` cannot find a matching vault entry for the paraphrased form and passes it through unchanged — the client sees an opaque token in the response rather than the original value. This is the failure mode motivating ADR-5's A/B test.

### 4.4 Strategy Mix

Different sensitivity categories call for different transformation strategies. The table below maps category to strategy and rationale.

| Category | Strategy | Rationale | Example |
|---|---|---|---|
| PII with structural meaning (email, phone, CCCD) | **Tokenize** → vault | Model needs to reason about the entity; round-trip restores value | `alice@vng.vn` → `EMAIL_01` |
| Numeric IDs (credit card, bank account) | **FPE (Format-Preserving Encryption)** (planned P2) | Downstream validation logic expects 16-digit numbers; FPE preserves digit count and Luhn checksum | `4111111111111111` → `4222000000000001` |
| API credentials, tokens, private keys | **Block** → reject request | No legitimate reason to send credentials to an AI; fail safe | JWT → 400 DLP_BLOCKED |
| Internal identifiers (package names, codenames) | **Tokenize** → vault | Model must reason about the identifier; round-trip restores for developer | `@vng/zalo-pay-internal-sdk` → `INTERNAL_PACKAGE_01` |
| Generic sensitive terms (deny list) | **Block** | Custom deny terms in `customDenyTerms` | `CompanyConfidential` → block |
| Statistical/hashed secrets (SHA hashes of PII used as DB keys) | **Hash** (planned P2) | Preserve database join semantics without revealing original | `sha256("alice@vng.vn")` → `sha256("EMAIL_01")` |
| Analyst-facing reports | **Pseudonymise** (planned P3) | Replace entity with stable fictional equivalent from a lookup table; enables cross-request analytics without linking to real identity | Customer ID `VNG-12345` → `CUST-AAAA` |

### 4.5 Bypass Workflow

Certain workflows legitimately require the AI to see real PII — for example, a support engineer debugging a production incident involving a specific customer's data, with CISO sign-off.

The bypass workflow (planned P3) works as follows:

1. Engineer submits a request to the CISO approval portal, providing: conversation purpose, data categories, expected data subjects, duration.
2. CISO (or delegated security reviewer) approves via the portal.
3. Portal issues a JWT with claims: `{ sub: "engineer@company.vn", convId: "<specific-conv>", bypass: ["email", "phone"], exp: now+900, maxUses: 1 }`.
4. Engineer includes the JWT as `X-OMC-Bypass-Token` header on the next request.
5. Proxy validates JWT signature (RS256 with CISO's key), checks `exp` and `maxUses`, logs a `bypass` audit event.
6. For that single request, tokenise policies for the listed classifiers are skipped.
7. `maxUses` is decremented to 0; token cannot be replayed.

**Hard constraint**: Bypass MUST NEVER be issued for `SECRET.*` classifiers (credentials, private keys). These are always blocked, no exception.

**Rationale**: The bypass window is 15 minutes (`exp: now+900`) and single-use to minimise the window for token theft. The JWT is not stored in the vault — it is verified and consumed in memory.

### 4.6 Audit and Compliance Chain

The audit system (`src/proxy/audit.ts`) emits one JSONL event per request phase. Phases: `request`, `response`, `tool`, `block`, `hitl`, `error`.

```typescript
// src/proxy/audit.ts:34-48
export interface AuditEvent {
  ts?: string;           // ISO-8601 UTC
  reqId: string;         // random UUID per request
  clientIp?: string;     // source IP (XFF-aware if configured)
  phase: AuditPhase;     // request | response | tool | block | hitl | error
  model?: string;        // e.g. "claude-3-5-sonnet-20241022"
  dlpMatches?: DlpMatchSummary[];  // [{name, policy, count}] — no raw values
  blocked?: boolean;
  bytesIn?: number;
  bytesOut?: number;
  latencyMs?: number;
  error?: string;        // DLP-scanned before write
  meta?: Record<string, string | number | boolean>;
}
```

**HMAC chain** (planned P3, currently: per-event fsync): In the P3 hardening phase, each audit event will include an HMAC of the previous event's hash to form a tamper-evident chain. This allows an auditor to verify that no event has been deleted or modified since the chain was written.

**Counter aggregation for Nghị định 13/2023**: The `dlpMatches` field provides classifier-level counts per request. A quarterly aggregation query over the JSONL files can produce a report of the form: "In Q1 2026, 0 requests containing `cccd_vn` classifier data were forwarded to Anthropic without redaction or tokenisation." This is the proof-of-non-egress artifact required for NĐ 13/2023 Art. 22 compliance.

The audit file mode is `0o600` (`src/proxy/audit.ts:94`), ensuring only the proxy process owner can read the audit log.

---

## 5. BA Extension — Source Code DLP

### 5.1 Use Cases US-9 to US-15

| ID | Title | Actor | Precondition | Main Flow | Success Outcome | Compliance Tie-in |
|---|---|---|---|---|---|---|
| US-9 | Refactor with internal-package safe | Developer | Developer pastes a TypeScript file that imports `@vng/zalo-pay-internal-sdk` and asks Claude to refactor it | Dictionary lane matches `@vng/zalo-pay-internal-sdk` → `INTERNAL_PACKAGE_01`; model reasons about `INTERNAL_PACKAGE_01`; detokenise restores real name | Developer receives refactored code; internal package name not in Anthropic API logs | Luật SHTT 2005 Điều 84 |
| US-10 | Stack-trace triage | Developer | Developer pastes a Java stack trace containing internal class paths (`com.vng.payment.internal.GatewayProcessor`) and internal hostnames | Stack-trace handler: top-3 + bottom-3 frames retained; middle collapsed; class paths tokenised | Claude can identify the error type and suggest fixes without seeing internal package structure depth | Luật SHTT 2005 Điều 84 |
| US-11 | SQL review | Developer | Developer pastes a `SELECT` query referencing internal table names and column names in a proprietary schema | SQL pipeline: parse → walk AST → tokenise identifiers → re-serialise; query structure preserved | Model receives syntactically valid SQL with tokenised identifiers; can review for injection, optimisation | Luật Cạnh tranh 2018 Điều 45 |
| US-12 | Dependency upgrade | Developer | Developer asks Claude to help upgrade `@vng/zalo-pay-internal-sdk` from v1 to v2, pasting `package.json` | Dictionary matches package name; tokenised in `package.json` content | Model provides upgrade guidance referring to `INTERNAL_PACKAGE_01`; developer understands |  Luật SHTT 2005 Điều 84 |
| US-13 | Codename brainstorm | Product Manager | PM asks Claude to suggest names for a new feature, mentioning `Project Bluefin` (existing unreleased product) as context | Dictionary matches `Project Bluefin` → `CODENAME_01`; model brainstorms in context of `CODENAME_01` | PM gets name suggestions; model cannot infer that `CODENAME_01` is a fish-named codename (competitor intel) | Luật Cạnh tranh 2018 Điều 45 |
| US-14 | Dictionary self-service | Security Engineer | Engineer needs to add 50 new internal package names without a proxy restart | Engineer submits names via self-service portal → Postgres → Redis pub-sub → worker thread rebuilds Aho-Corasick automaton | New terms active within seconds; no proxy downtime | Internal policy |
| US-15 | Compliance audit (code egress) | Auditor | Auditor queries audit JSONL for evidence that `INTERNAL_PACKAGE` identifiers were tokenised, not forwarded raw | Auditor runs audit query for `dict:INTERNAL_PACKAGE` in `dlpMatches`; verifies count | Audit evidence produced for IP protection review | Luật SHTT 2005 Điều 84 |

### 5.2 Twelve New Entity Classes

The following twelve entity classes extend the four already shipped (INTERNAL_PACKAGE, CODENAME, PARTNER_NAME, INTERNAL_HOST). Each class specifies its detection lane and a shape-preserving token grammar.

| Class Name | Description | Example | Detection Lane | Token Grammar |
|---|---|---|---|---|
| `INTERNAL_PACKAGE` | Internal npm/Maven/PyPI package not published publicly | `@vng/zalo-pay-internal-sdk` | Dictionary (case-sensitive AC) | `PKG_01` → `@scope/internal-pkg-01` |
| `CODENAME` | Unreleased product or project codename | `Project Bluefin`, `Project Redwood` | Dictionary (case-insensitive AC) | `CN_01` → `Project Codename-01` |
| `PARTNER_NAME` | Named external business partner under NDA | `Vietcombank`, `VPBank` | Dictionary (case-insensitive AC) | `PARTNER_01` → `Partner-01` |
| `INTERNAL_HOST` | Internal DNS name not in public DNS | `gitlab.company.internal`, `redis.prod.internal` | Dictionary (case-insensitive AC) | `HOST_01` → `host-01.internal` |
| `INTERNAL_CLASS_PATH` | Fully qualified Java/Kotlin/Scala class in internal package | `com.vng.payment.GatewayProcessor` | Regex: `\bcom\.(vng|acme)\.[a-z.]+\.[A-Z][A-Za-z]+\b` or dictionary | `CLASSPATH_01` → `com.example.A01` |
| `BRAND_VS_COMPETITOR` | Competitor brand name used in internal comparison docs | `MoMo`, `ZaloPay` (as competitor, not as own brand) | Dictionary | `BRAND_01` → `Brand-01` |
| `TICKET_REF` | Internal Jira/Linear/GitHub issue reference | `VNG-1234`, `PROJ-5678` | Regex: `\b[A-Z]{2,6}-\d{3,6}\b` | `TICKET_01` → `TICKET-01` |
| `AUTHOR_TAG` | Git commit author tag or `@mention` of internal employee | `@nguyen.van.a`, `// Author: Nguyen Van A` | Regex: `@[a-z.]{3,}` in code comments | `AUTHOR_01` → `@author-01` |
| `DB_SCHEMA_IDENT` | Internal database table, column, or schema name | `tbl_payment_gateway`, `schema_hr_private` | AST (SQL parser) + dictionary prefix | `SCHEMA_01` → `tbl_schema_01` |
| `ML_MODEL_NAME` | Internal ML model name not published externally | `vng-llm-viet-7b`, `payment-fraud-v3` | Dictionary | `MODEL_01` → `model-01` |
| `INTERNAL_API_ENDPOINT` | Internal API endpoint path | `/internal/v1/payment/process`, `/api/admin/users` | Regex: `/internal/`, `/admin/` prefixes | `ENDPOINT_01` → `/internal/endpoint-01` |
| `FILE_PATH_INTERNAL` | Absolute file path revealing internal directory structure | `/home/deploy/app/vng-payment/config.yaml` | Regex: absolute paths with depth ≥ 3 | `PATH_01` → `/internal/path-01` |

**Sample dictionary entries illustrating the current four classes** (`src/proxy/sample-dictionary.json`):

```json
[
  {"term": "@vng/zalo-pay-internal-sdk", "classifier": "INTERNAL_PACKAGE", "policy": "tokenize"},
  {"term": "@acme/billing-core",         "classifier": "INTERNAL_PACKAGE", "policy": "tokenize"},
  {"term": "Project Bluefin",            "classifier": "CODENAME",         "policy": "tokenize"},
  {"term": "Project Redwood",            "classifier": "CODENAME",         "policy": "tokenize"},
  {"term": "Vietcombank",                "classifier": "PARTNER_NAME",     "policy": "tokenize"},
  {"term": "gitlab.company.internal",    "classifier": "INTERNAL_HOST",    "policy": "tokenize"}
]
```

### 5.3 Functional Requirements FR-13 to FR-21

| ID | Statement | Priority | Measurable Acceptance |
|---|---|---|---|
| FR-13 | The proxy MUST support shape-preserving tokenisation for source-code identifiers so that downstream parsers (TypeScript, Java, SQL) still succeed on tokenised code | P1 | Tokenised TypeScript compiles with `tsc --noEmit`; tokenised SQL parses with `node-sql-parser` |
| FR-14 | Code comments containing PII or sensitive identifiers MUST be redacted before the code reaches the AI | P1 | Test: `// email: alice@vng.vn` → `// email: [REDACTED:email]` |
| FR-15 | SQL queries MUST remain syntactically valid after tokenisation of table and column identifiers | P1 | Round-trip test: parse before and after; both ASTs structurally equivalent |
| FR-16 | Stack traces MUST be depth-collapsed: keep top-3 and bottom-3 frames; collapse the middle with `... (N frames elided) ...` | P2 | Test with a 20-frame stack trace; assert 7 frames visible |
| FR-17 | Absolute file paths deeper than 3 levels MUST be normalised to remove host-specific prefix | P2 | `/home/deploy/app/vng-payment/config.yaml` → `/internal/path-01/config.yaml` |
| FR-18 | A dictionary self-service portal MUST allow authorised engineers to add new terms without proxy restart | P2 | New term active within 30 seconds of submission; verified by integration test |
| FR-19 | The AST lane MUST be gated behind `OMC_PROXY_AST_DLP=1` feature flag and default-off | P2.5 | If env var absent, AST lane skipped; latency ≤ 100ms p95 without AST |
| FR-20 | The system MUST support an `anonymize-company` mode that replaces all company-specific tokens with generic placeholders when sharing code externally | P3 | All INTERNAL_PACKAGE, CODENAME, PARTNER_NAME tokens replaced with generic `PKG_NN`, `CN_NN`, `PARTNER_NN` |
| FR-21 | Round-trip SLA: a tokenised request MUST be detokenised within 5ms of the upstream response arriving, measured in the proxy | P1 | Benchmark: 10k round-trips; p99 detokenise latency ≤ 5ms |

### 5.4 Risks R-11 to R-17

| ID | Description | Likelihood | Impact | Mitigation | Residual |
|---|---|---|---|---|---|
| R-11 | **Token namespace collision**: `EMAIL_01` issued by regex lane and `INTERNAL_PACKAGE_01` both happen to be generated at the same time in different classifiers with the same `_01` suffix, causing lookup ambiguity | Low | Medium | Token format includes classifier prefix (`EMAIL_01` vs `INTERNAL_PACKAGE_01`); regex `TOKEN_REGEX` matches any classifier; lookup is by exact token string | Very Low |
| R-12 | **tree-sitter parse failures on malformed code**: developer pastes a code snippet with a syntax error; AST parser throws; proxy falls back to regex-only, potentially missing AST-detectable identifiers | Medium | Low | AST lane is a best-effort enhancement; parse failure triggers fallback to regex + dictionary; audit event logged with `meta.ast_fallback: true` | Low |
| R-13 | **node-sql-parser version drift**: internal SQL dialect uses vendor-specific syntax (MySQL `GROUP_CONCAT`, PostgreSQL `JSONB` operators) that the parser does not support | Medium | Medium | Pin `node-sql-parser` version; test against company dialect on upgrade; dialect-specific fallback to regex for `SELECT`/`FROM`/`WHERE` identifiers | Medium |
| R-14 | **Dictionary poisoning via self-service**: an attacker with self-service portal access adds a very broad term (e.g., `the`) that tokenises almost every word | Low | High | Self-service portal enforces: minimum term length of 4 characters; no regex (literal only); reviewer approval for terms matching >0.1% of a sample corpus; rate limiting | Low |
| R-15 | **Shape-preserving token confuses compile-time type checker**: `INTERNAL_PACKAGE_01` as a package name in `package.json` is not a valid npm package scope; TypeScript's module resolver fails | Medium | Low | Document that tokenised code is for AI review only, not compilation; add warning to proxy response headers | Low |
| R-16 | **Stack-trace depth collapse hides root cause**: collapsing the middle 14 frames of a 20-frame trace removes the specific internal library call that is the actual bug | Medium | Medium | Keep bottom-3 frames which typically contain the root cause; top-3 for context; allow configurable keep-count | Medium |
| R-17 | **Regex false negative for INTERNAL_CLASS_PATH**: an internal class in an unusual package like `io.company.X` instead of `com.company.X` misses the regex | Medium | Low | Dictionary lane entries for root packages; engineers add `io.company` to dictionary; regex extended with configurable prefix list | Low |

### 5.5 Compliance: Trade Secret and Unfair Competition Law

#### Luật Sở hữu trí tuệ 2005 (Intellectual Property Law), Điều 84 — Trade Secret Protection

Article 84 defines a trade secret as information satisfying three conditions:
1. Not generally known or readily accessible by persons in the sectors that normally deal with such information.
2. Confers actual or potential commercial advantage on its holder.
3. Is kept confidential by its holder through reasonable measures.

Internal package names like `@vng/zalo-pay-internal-sdk`, project codenames like `Project Bluefin`, and internal API endpoints satisfy all three conditions. The AI egress proxy constitutes the "reasonable measures" required by condition 3 — it prevents these identifiers from being transmitted to third-party AI processors where they could appear in API logs, training data, or monitoring dashboards accessible to Anthropic employees.

Without the proxy, sending these identifiers to the Anthropic API could be argued to undermine condition 3: the organisation is voluntarily disclosing the trade secret to a third party without contractual protections that fully prevent that third party from accessing or retaining the information.

#### Luật Cạnh tranh 2018 (Competition Law), Điều 45 — Prohibition of Unfair Competition Acts

Article 45 prohibits acts of unfair competition including: "Accessing, collecting or using confidential business information without the consent of the party that has the right to use it." Confidential business information includes business strategies, plans, and partner relationships.

Competitor intelligence derived from an organisation's AI prompts — for example, the names of banking partners appearing in internal code — would constitute a breach of this article if obtained through the AI provider's infrastructure. The proxy ensures that `PARTNER_NAME` entities (e.g., `Vietcombank` in the context of an internal payment SDK) are replaced with opaque tokens before reaching the Anthropic API endpoint.

**Practical implication for the proxy design**: The source code DLP layer is not optional "nice to have" functionality — it is a legal control required to preserve trade secret status and avoid unfair competition liability.

---

## 6. SA Extension — Source Code Layer

### 6.1 Four-Lane Detector Architecture

```mermaid
flowchart LR
    Input[Source code string\nor file content] --> R[Lane 1: Regex\nsrc/proxy/dlp.ts:scan]
    Input --> D[Lane 2: Dictionary\nsrc/proxy/dictionary.ts]
    Input --> AST[Lane 3: AST\ntree-sitter + node-sql-parser\nPlanned P2.5]
    Input --> H[Lane 4: Heuristic\nentropy / pattern density]

    R --> M[Merge\ndedup\nlongest-leftmost]
    D --> M
    AST --> M
    H --> M

    M --> AP[applyPolicy\ntokenize / redact / block]
    AP --> Out[Transformed source\nwith vault tokens]
```

**Lane 1 — Regex**: Fast, O(n × patterns). Handles TICKET_REF (`[A-Z]{2,6}-\d{3,6}`), AUTHOR_TAG (`@[a-z.]{3,}` in comments), INTERNAL_API_ENDPOINT (`/internal/`, `/admin/` prefixes), FILE_PATH_INTERNAL (absolute paths ≥3 levels deep). Also handles the existing credential patterns.

**Lane 2 — Dictionary (Aho-Corasick)**: Handles exact-match identifiers: INTERNAL_PACKAGE, CODENAME, PARTNER_NAME, INTERNAL_HOST, ML_MODEL_NAME, BRAND_VS_COMPETITOR. Zero-dependency TypeScript implementation in `src/proxy/dictionary.ts`. Hot-reload via `Dictionary.reload()` (`src/proxy/dictionary.ts:78-101`).

**Lane 3 — AST** (planned P2.5, gated behind `OMC_PROXY_AST_DLP=1`): Handles DB_SCHEMA_IDENT (SQL table/column names) via `node-sql-parser`, and INTERNAL_CLASS_PATH in Java/TypeScript via tree-sitter. The AST lane is the only lane that requires external npm dependencies (`tree-sitter`, `node-sql-parser`), which is why it is feature-flagged.

**Lane 4 — Heuristic**: Shannon entropy analysis to detect high-entropy strings (likely encoded secrets: base64-encoded keys, hex-encoded hashes). This runs in addition to the pattern-specific lanes and catches novel credential formats not yet covered by regex. Output feeds into the `block` policy.

**Merge strategy**: All four lanes produce `(start, end, classifier, policy)` tuples. These are merged identically to the PII layer: sorted by `start`, ties broken by `end` descending (longest match wins), cursor advances left-to-right skipping overlaps.

### 6.2 Token Grammar — Shape-Preserving Substitutions

The fundamental requirement for source-code tokenisation is that the substituted token must be syntactically valid in the language where it appears. An opaque UUID (`3f2504e0-4f89-11d3`) would break an `import` statement, an SQL query, and a Java class instantiation simultaneously.

The following table defines shape-preserving token grammars for each of the ten most common substitution shapes:

| Token Class | Original Example | Token | Shape Rule | Preserved Property |
|---|---|---|---|---|
| `INTERNAL_PACKAGE` | `@vng/zalo-pay-internal-sdk` | `@scope/internal-pkg-01` | `@scope/internal-pkg-NN` | Valid npm scoped package name |
| `CODENAME` | `Project Bluefin` | `Project Codename-01` | `Project Codename-NN` | `Project <Word>` pattern recognisable to model as a codename |
| `PARTNER_NAME` | `Vietcombank` | `Partner-01` | `Partner-NN` | Single word, no special chars |
| `INTERNAL_HOST` | `gitlab.company.internal` | `host-01.internal` | `host-NN.internal` | Valid FQDN ending in `.internal` |
| `INTERNAL_CLASS_PATH` | `com.vng.payment.GatewayProcessor` | `com.example.A01` | `com.example.ClassNN` | Valid Java FQDN; compiles if used as type name |
| `DB_SCHEMA_IDENT` | `tbl_payment_gateway` | `tbl_schema_01` | `tbl_schema_NN` | Valid SQL identifier; snake_case preserved |
| `TICKET_REF` | `VNG-1234` | `TICKET-01` | `TICKET-NN` | Valid Jira-style key |
| `AUTHOR_TAG` | `@nguyen.van.a` | `@author-01` | `@author-NN` | Valid git/Slack mention format |
| `ML_MODEL_NAME` | `vng-llm-viet-7b` | `model-01` | `model-NN` | Generic kebab-case identifier |
| `INTERNAL_API_ENDPOINT` | `/internal/v1/payment/process` | `/internal/endpoint-01` | `/internal/endpoint-NN` | Valid URL path prefix preserved |

**The "realistic substitution" reject**: ADR-5 records the decision not to use realistic substitutions (e.g., replacing `Vietcombank` with `Acme Bank`). Realistic substitutions are dangerous because:
1. They create a false impression that the AI is reasoning about `Acme Bank`, which may confuse the developer when they read the response.
2. Round-trip restoration is identical to the `tokenize` strategy but adds the risk of domain confusion.
3. If the realistic replacement happens to be a real competitor name, the prompt now contains competitor intelligence.

### 6.3 SQL Pipeline

SQL presents a special challenge because it contains both structural keywords (SELECT, FROM, WHERE — which must not be tokenised) and user-defined identifiers (table names, column names, schema names — which must be tokenised if they are internal).

```
Input SQL:
  SELECT u.email, p.account_balance
  FROM tbl_user_private u
  JOIN tbl_payment_gateway p ON u.id = p.user_id
  WHERE u.created_at > '2025-01-01'

Pipeline:
  1. Sniff: does string start with SELECT/INSERT/UPDATE/DELETE/CREATE?
  2. Parse: node-sql-parser → AST
  3. Walk AST: visit TableRef nodes → tokenise if in dictionary or prefix-match
  4. Walk AST: visit ColumnRef nodes → tokenise if in dictionary
  5. Re-serialise: node-sql-parser AST → SQL string

Output SQL:
  SELECT u.email, p.SCHEMA_02
  FROM SCHEMA_01 u
  JOIN SCHEMA_03 p ON u.id = p.user_id
  WHERE u.created_at > '2025-01-01'

Vault mappings:
  SCHEMA_01 → tbl_user_private
  SCHEMA_02 → account_balance
  SCHEMA_03 → tbl_payment_gateway
```

The re-serialised SQL is syntactically valid and can be submitted to the AI model for query optimisation or injection analysis. Note that `u.email` is left for the regex lane to handle (it will be tokenised as an `EMAIL` if the email regex matches, or left if it's just a column reference without a value).

**Parsability guarantee**: The pipeline catches `node-sql-parser` exceptions; if parsing fails (dialect mismatch, malformed SQL), it falls back to regex-only scanning and logs `meta.sql_parse_fallback: true` in the audit event.

### 6.4 Stack-Trace Handling

A typical Java stack trace sent to an AI for debugging contains 20–40 frames. Most of the middle frames are framework internals (Spring, Netty, Jackson) that are not sensitive and not useful for debugging. The critical frames are:

- **Top 3**: The exception type, message, and immediate throw site — where the error manifests.
- **Bottom 3**: The entry point (e.g., HTTP handler, Kafka consumer, main method) — where execution originated.

The middle frames often contain internal class paths at depth.

**Transformation rule**:

```
Input (20 frames):
  com.vng.payment.GatewayProcessor.processPayment(GatewayProcessor.java:142)
  com.vng.payment.GatewayProcessor.validate(GatewayProcessor.java:98)
  com.vng.payment.internal.BalanceChecker.check(BalanceChecker.java:55)
  ... [14 internal framework frames] ...
  org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)
  org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:963)
  com.vng.api.PaymentController.createPayment(PaymentController.java:88)

Output (7 frames + elision notice):
  CLASSPATH_01.processPayment(GatewayProcessor.java:142)
  CLASSPATH_01.validate(GatewayProcessor.java:98)
  CLASSPATH_02.check(BalanceChecker.java:55)
  ... (14 frames elided) ...
  org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)
  org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:963)
  CLASSPATH_03.createPayment(PaymentController.java:88)
```

Spring framework class paths are not tokenised (they are publicly known). Only the internal `com.vng.*` paths are tokenised using the `INTERNAL_CLASS_PATH` classifier.

### 6.5 Codename Dictionary Self-Service

The codename dictionary grows as new products are named. Requiring a proxy restart for every new entry creates operational friction and risks a gap period where new codenames are not protected.

**Architecture**:

```mermaid
flowchart LR
    Portal[Self-service Portal\nWeb UI] --> PG[Postgres\nSource of truth\nterms table]
    PG --> W[Worker Thread\nin proxy process]
    PG --> |pg_notify / Redis pub-sub| R[Redis\nhot-reload channel]
    R --> W
    W --> |Dictionary.reload| D[Aho-Corasick\nautomaton]
    D --> |scan| Req[Request handler\nmain thread]
```

**Steps**:
1. Engineer submits new term via portal (authenticated, role-based access).
2. Portal validates term (minimum length 4, no regex metacharacters, reviewer approval if term matches >0.1% of sample).
3. Term written to `terms` table in Postgres with `approved = true`.
4. Postgres `pg_notify` or Redis pub-sub broadcasts a reload event.
5. Proxy's background worker thread receives event, queries Postgres for all approved terms, calls `Dictionary.reload(entries)`.
6. `Dictionary.reload()` (`src/proxy/dictionary.ts:78-101`) rebuilds both automatons (CS and CI) atomically. The main request-handling thread sees the new automaton on the next request.

**Why worker thread**: Rebuilding a large Aho-Corasick automaton (10k+ terms) takes 10–50ms. Doing this on the main Node.js event loop would stall all in-flight requests for that duration. Rebuilding in a worker thread (or a `setImmediate`-deferred microtask if the term count is small) keeps the request loop responsive.

### 6.6 Defensive Detokenization

Detokenisation has two layers of defense against vault-miss (token appears in response but is not in the vault):

**Layer 1 — System-prompt anchor**: `injectDlpInstruction` (`src/proxy/dlp.ts:316-333`) tells the model to preserve tokens verbatim. If the model obeys, all tokens in the response will be exact-match lookable in the vault.

**Layer 2 — Pass-through for unknown tokens**: `detokenize` (`src/proxy/dlp.ts:436-447`) uses `String.replace` with a callback that returns the vault lookup if found, or the original token if not found. Unknown tokens pass through unchanged rather than being replaced with an error string. This avoids corrupt output when the model correctly outputs a token that refers to a different conversation (which should not happen if conv-scoping is correct, but defensive programming applies).

**Failure mode visibility**: If a token appears in the developer's response that they do not recognise, they know the vault missed. The next step is to check the audit log for the `detokenize` events and verify that the `convId` in the request matched the vault scope.

### 6.7 Performance Budget

The overall latency budget for the code path is ≤ 130ms p95, measured as proxy-internal overhead excluding upstream API latency.

| Processing Step | Estimated p95 Latency | Notes |
|---|---|---|
| JSON parse of request body | ~1ms | Node.js built-in JSON parser; 100KB typical request |
| Regex lane (9 default patterns) | ~2ms | All patterns global, linear scan |
| Dictionary lane (Aho-Corasick, 1k terms) | ~3ms | O(n) over text; automaton already built |
| Dictionary lane (Aho-Corasick, 10k terms) | ~5ms | Automaton size grows but scan remains O(n) |
| Vault issue/lookup (in-process Map) | <1ms | Hash map lookup, O(1) |
| System-prompt injection | <1ms | String prepend |
| JSON serialise tokenised body | ~1ms | |
| **Subtotal: PII-only path** | **~8ms p95** | Well within budget |
| SQL parse (node-sql-parser) | ~10ms | Per query; only when SQL detected |
| tree-sitter parse (TypeScript) | ~20ms | Per file; only when AST lane enabled |
| Aho-Corasick rebuild (hot-reload, 1k terms) | ~5ms | In worker thread; does not block request |
| SSE detokenise per frame | <1ms | Regex replace over typically small delta |
| **Subtotal: full code path with AST** | **~40ms p95** | Meets budget (130ms) |

The +30–50ms budget for the code DLP layer over the PII-only baseline is consumed by SQL parsing and tree-sitter, which is why the AST lane is feature-flagged (FR-19). Operators can enable it only when their request mix justifies the latency.

---

## 7. Migration Plan

### Phase 1 — P1: Vault + PII (DONE ✅ `8f04b25`)

Steps 1–5 are complete as of commit `8f04b25`.

| Step | Deliverable | Owner | Exit Criteria | Rollback |
|---|---|---|---|---|
| 1 ✅ | `TokenVault` interface in `vault.ts` | Platform | Interface merged; compiles | Revert commit |
| 2 ✅ | `InProcessTokenVault` implementation with NFC/case-fold keying and TTL | Platform | `vault.test.ts` all 12 tests pass | Revert commit |
| 3 ✅ | `tokenize` policy in `applyPolicy` + vault round-trip | Security Eng | `dlp.test.ts` tokenise tests pass | Disable tokenize patterns in config |
| 4 ✅ | `Dictionary` (Aho-Corasick) + `sample-dictionary.json` + 4 entity classes | Platform | `dictionary.test.ts` all 9 tests pass | Set `dictionary.entries: []` in config |
| 5 ✅ | `SseDetokenizer` class + integration with `startProxy` streaming path | Platform | `server.integration.test.ts` SSE round-trip test passes | Disable tokenize policy; SseDetokenizer is no-op if no vault tokens in stream |

**Verification**: `npm run test:run` → 94/94 green, `npx tsc --noEmit` → 0 errors.

---

### Phase 2 — P2: Presidio NER + 4 Code Classes + Self-Service Portal

Steps 6–10. Estimated calendar time: 6–8 weeks.

| Step | Deliverable | Owner | Exit Criteria | Rollback |
|---|---|---|---|---|
| 6 | Deploy Presidio NER sidecar (self-hosted, Vietnamese locale) with `underthesea` integration | Platform / ML | Sidecar passes Vietnamese person-name and address NER tests; latency ≤ 40ms p95 | Disable NER lane via config flag; fall back to regex + dict |
| 7 | Integrate Presidio sidecar into detection pipeline as Layer 3 | Security Eng | Integration tests: Vietnamese name `Nguyễn Văn A` correctly classified as `PERSON`; no false positives on common Vietnamese words | Toggle off NER in config |
| 8 | Add 4 new entity classes to dictionary: `INTERNAL_CLASS_PATH` (regex), `BRAND_VS_COMPETITOR` (dict), `TICKET_REF` (regex), `AUTHOR_TAG` (regex) | Security Eng | Each class has ≥ 5 passing unit tests; integration test with sample code | Remove patterns from config |
| 9 | Self-service dictionary portal MVP: web UI + Postgres backend + approval workflow | Platform | Engineer can add term → appears in Dictionary within 30s; audit log records addition | Revert to file-based dictionary |
| 10 | Redis pub-sub hot-reload: portal writes to Postgres, worker thread rebuilds automaton | Platform | Hot-reload latency ≤ 2s from write to effective; no request-loop stall | Static dictionary file reload on SIGHUP as fallback |

---

### Phase 2.5 — P2.5: AST Lane (NEW)

Steps 11–13. Feature-flagged behind `OMC_PROXY_AST_DLP=1`. Estimated calendar time: 4 weeks.

**Why gated**: The AST lane adds `tree-sitter` and `node-sql-parser` as runtime dependencies. These are heavier dependencies than the zero-dep dictionary lane, and their per-request latency (10–20ms) makes them unsuitable for high-throughput deployments. The flag lets platform teams enable them only where the sensitivity of the code justifies the cost.

| Step | Deliverable | Owner | Exit Criteria | Rollback |
|---|---|---|---|---|
| 11 | SQL pipeline: sniff → `node-sql-parser` → walk AST → tokenise identifiers → re-serialise | Security Eng | Round-trip test: original SQL and tokenised SQL parse to structurally equivalent ASTs; DB_SCHEMA_IDENT class active | Disable with `OMC_PROXY_AST_DLP=0` |
| 12 | tree-sitter TypeScript/JavaScript parser lane: INTERNAL_CLASS_PATH detection in TS `import` statements and Java FQDN references | Security Eng | Tokenised TypeScript compiles with `tsc --noEmit`; Java FQDN correctly tokenised | Disable with `OMC_PROXY_AST_DLP=0` |
| 13 | Stack-trace depth collapse: top-3 + bottom-3 + elision | Security Eng | Test with 20-frame trace: 7 frames emitted; elision count correct | Remove stack-trace handler; pass full trace (less protection) |

---

### Phase 3 — P3: Bypass Workflow + KMS + Multi-Tenant

Steps 14–16. Estimated calendar time: 8–12 weeks.

| Step | Deliverable | Owner | Exit Criteria | Rollback |
|---|---|---|---|---|
| 14 | Bypass JWT workflow: CISO approval portal, JWT RS256, `maxUses=1`, 15-min TTL, audit logging | Security Eng / CISO | End-to-end test: approved bypass skips tokenise for listed classifiers; second use rejected; `bypass` audit event logged | Disable bypass; require all requests to use tokenise |
| 15 | Redis-backed `TokenVault` + envelope encryption (DEK per conversation, KEK in KMS) | Platform | Vault survives proxy restart; benchmark: `vault.issue` latency ≤ 10ms p95 including Redis round-trip; KMS key rotation test | Revert to `InProcessTokenVault` (data loss on restart) |
| 16 | Multi-tenant vault isolation: `tenantId` field on `DictionaryEntry` and `TokenVault` methods; separate Redis keyspace per tenant | Platform | Tenant A tokens not visible to Tenant B; audit events include `tenantId` | Single-tenant mode (no isolation) |

---

## 8. Architecture Decision Records

### ADR-1: Masking Mode — Layered Strategy (tokenize + FPE + hash + block)

**Status**: Accepted. Implemented in `8f04b25`.

**Context**: The proxy must handle multiple categories of sensitive data with fundamentally different requirements. Credentials (JWT, API keys) must never reach the AI — there is no legitimate use case. PII (email, phone, CCCD) needs to be visible to the AI structurally (the model should know a value is an email address) but the real value must not egress. Internal identifiers (package names, codenames) need to survive round-trip so the developer can work with real names in the response.

**Decision**: Use a four-strategy layered approach:
1. **Block** — for credentials and high-RESTRICTED data. Request rejected at the proxy. Zero risk of egress.
2. **Redact** — for INTERNAL tier data where structural meaning is not needed. Replace with `[REDACTED:classifier]`.
3. **Tokenize** — for CONFIDENTIAL tier PII and source-code identifiers. Issue a vault token (`EMAIL_01`); detokenise on response. Reversible within conversation scope.
4. **FPE (planned P2)** — for format-sensitive numeric IDs (bank accounts, credit cards). Preserves digit count and checksum so downstream validators pass.

**Consequences**:
- Developers retain the ability to work with real code structures (the AI sees `EMAIL_01`, not `[REDACTED]`, so it can reason about email validation logic).
- Round-trip adds complexity: `InProcessTokenVault`, `SseDetokenizer`, system-prompt injection.
- Token paraphrase is a live risk (ADR-5, R-4).

**Alternatives considered**:
- *Pure redaction* (replace all sensitive data with static strings): Simpler, but breaks AI usefulness — the model sees `[REDACTED]` and cannot reason about the structure of the original data. Rejected.
- *Pure blocking* (reject any request with sensitive content): Maximally safe, but developers would bypass the proxy entirely to get useful AI assistance. Rejected.
- *Pure passthrough with contractual controls* (rely on Anthropic's DPA): Insufficient under NĐ 13/2023 — technical controls are required alongside contractual ones. Rejected.

**Confidence**: High.

---

### ADR-2: Vault Storage — Redis + Envelope Encryption

**Status**: Decided. In-process implementation shipped; Redis phase planned for P3.

**Context**: The `TokenVault` interface requires: persist token-to-original mappings for the duration of a conversation (up to 24h), survive proxy restarts in production, support per-conversation TTL, and meet data residency requirements (tokens map to Vietnamese PII; the backing store must be in a Vietnamese datacenter or at least not in a foreign cloud).

**Decision**: Ship `InProcessTokenVault` as a functional PoC (no external dep, zero latency). Replace with `RedisTokenVault` in P3. Redis stores AES-256-GCM encrypted values; DEK per conversation stored in Redis under a KEK managed by an on-premise KMS (HashiCorp Vault or a Vietnamese HSM service).

**Consequences**:
- Redis adds operational complexity (cluster management, replication, failover).
- Envelope encryption adds ~1ms per vault operation (KMS DEK lookup is cached per conversation).
- Data residency is maintained: Redis and KMS are on-premise.

**Alternatives considered**:
- *SQLite as vault backing store*: SQLite has no TTL pressure mechanism — expired rows accumulate and require explicit `DELETE ... WHERE expires_at < NOW()` janitor jobs (Redis expires keys lazily at O(1) on access, no janitor needed). Concurrent read/write across multiple proxy instances requires WAL or a queuing writer; WAL's `fsync` on checkpoint typically adds ~1–5 ms per write on SSD versus Redis's sub-millisecond `SET EX` (see Redis benchmarks: ~0.3–0.5 ms p50 on localhost). Under the NFR-3 latency budget (≤80 ms p95 added over baseline), reserving 1–5 ms per tokenisation lookup for the vault alone is too expensive — a single prompt may tokenise 5–10 distinct entities. Rejected.
- *Skyflow (cloud tokenisation vault)*: Skyflow would simplify vault management but stores data in Skyflow's US/EU data centres. Sending CCCD-class PII to a foreign controller would trigger NĐ 13/2023 **Điều 25** (mandatory Data Protection Impact Assessment for Cross-Border Transfer, DPIA-CBT, filed with A05/Bộ Công an) and **Điều 26** (incident notification to A05 within 60 days of any data breach affecting transferred data). Combined with the Điều 22 transfer-condition requirement, the compliance overhead and ongoing A05 reporting obligation make Skyflow non-viable for this use case. Rejected on data-residency grounds.
- *In-process only (no production persistence)*: Acceptable for single-instance developer tools, not for a fleet deployment where any proxy instance restart loses tokens mid-conversation. Kept as interim PoC only.

**Confidence**: High.

---

### ADR-3: Detection — Hybrid Regex + Dictionary In-TypeScript + Presidio NER Sidecar

**Status**: Accepted. Regex + dictionary shipped in `8f04b25`; NER sidecar planned for P2.

**Context**: DLP detection must cover three categories of sensitivity with different detection mechanisms: (1) structured patterns (email, CCCD — regex is sufficient); (2) exact-match identifiers (package names, codenames — Aho-Corasick is optimal); (3) contextually inferred PII (Vietnamese personal names, addresses — NER required).

**Decision**: Implement regex and dictionary entirely in TypeScript (zero extra runtime deps, <1ms per layer). Defer NER to a self-hosted Presidio sidecar with a Vietnamese NER model, called via localhost HTTP. This architecture keeps the fast path in-process and the slow path out-of-process.

**Consequences**:
- The sidecar must be deployed alongside the proxy in production (Docker Compose / Kubernetes sidecar container).
- Sidecar call adds ~20–40ms to requests that trigger it; the total budget of 130ms accommodates this.
- Self-hosting Presidio ensures Vietnamese PII is not sent to a third-party NLP cloud service (which would defeat the proxy's purpose).

**Alternatives considered**:
- *Google Cloud DLP API*: Excellent Vietnamese language support, but sending data to `dlp.googleapis.com` is the exact data-egress problem the proxy is preventing. Rejected.
- *AWS Comprehend Medical*: Same objection — third-party cloud ingestion. Rejected.
- *Pure rule-based detection (no NER)*: Regex can cover CCCD, MST, BHXH, phone. Cannot reliably detect unstructured PII like names and addresses in Vietnamese text. Vietnamese names have no fixed structure (can be 2–4 words, any word can be a surname or given name). Rejected for comprehensive PII coverage.
- *semgrep for code pattern detection*: semgrep is a powerful semantic code analysis tool, but it is designed for batch scanning of large codebases, not sub-millisecond per-request inline filtering. Its startup cost and rule compilation make it unsuitable for the proxy's request path. Rejected for the inline lane (considered for offline audit scanning).

**Confidence**: High.

---

### ADR-4: Code-Aware Detection — tree-sitter + node-sql-parser Embedded

**Status**: Decided. Implementation planned for P2.5.

**Context**: Source code sent to the AI often contains sensitive identifiers in syntactically significant positions: import statements, SQL FROM clauses, Java FQDN type references. Regex can find these but cannot distinguish a table name from a column alias or a string literal. AST-based detection is required for high-precision tokenisation that does not break the code.

**Decision**: Embed `tree-sitter` (TypeScript/JavaScript/Java grammar) and `node-sql-parser` directly in the proxy process, feature-flagged behind `OMC_PROXY_AST_DLP=1`. This avoids IPC latency and allows the AST lane to run inline in the same event loop turn as the regex and dictionary lanes.

**Consequences**:
- `tree-sitter` adds ~3MB to the production binary.
- `node-sql-parser` supports MySQL, PostgreSQL, and SQLite dialects; vendor-specific extensions (e.g., `JSONB`, `ARRAY_AGG` variants) may require fallback to regex.
- AST lane latency: ~10–20ms per request. Feature flag prevents this from affecting baseline deployments.

**Alternatives considered**:
- *semgrep sidecar*: semgrep can detect semantic patterns in code but is designed for batch scanning, not per-request inline filtering. Invoking semgrep as a sidecar per request would add 200–500ms latency and require spawning a Python process. Rejected.
- *CodeShield / Credentialdigger*: Focused on credential detection, not general identifier tokenisation. Rejected.
- *LSP (Language Server Protocol) integration*: LSP servers (e.g., TypeScript language server) can resolve identifiers semantically but require a full project context and take seconds to initialise. Unsuitable for per-request use. Rejected.

**Confidence**: High.

---

### ADR-5: Token Grammar for Source-Code Identifiers — Language-Syntax-Preserving

**Status**: Accepted with medium confidence. A/B test planned.

**Context**: When source-code identifiers are tokenised, the substituted token appears in positions that language parsers will evaluate: `import 'TOKEN'`, `FROM TOKEN`, `new TOKEN()`. The token format must not break the parser. Additionally, the model must not be confused by the token into producing incorrect output (e.g., inferring that a fictional package name is a real public package and hallucinating its API).

**Decision**: Use language-syntax-preserving tokens: `@scope/internal-pkg-NN` for npm packages, `host-NN.internal` for hostnames, `com.example.ClassNN` for Java FQDNs, `tbl_schema_NN` for SQL identifiers. These tokens are valid in their respective syntactic positions, allowing parsers to succeed, while being obviously artificial (non-existent packages, `.internal` TLD) to prevent model hallucination of real APIs.

**Consequences**:
- Token format is harder to define and test — must validate against actual parsers.
- Shape-specific grammars must be extended for each new entity class.
- The `NN` suffix allows the model to correlate multiple references to the same identifier within a file.

**Alternatives considered**:
- *Opaque UUID token* (e.g., `3f2504e0-4f89-11d3-9a0c-0305e82c3301`): Guaranteed unique, no grammar to define, but breaks every parser (`import '3f2504e0...'` is not valid ESM; `FROM 3f2504e0` is not valid SQL). Rejected.
- *Realistic substitution* (replace `Vietcombank` with `Acme Bank`): Looks natural in context but creates three problems: (1) model may hallucinate Acme Bank's real API; (2) if the substitution is a real competitor name, the prompt contains competitor intelligence; (3) domain confusion for the developer reading the response. Rejected.
- *Generic short token* (`T1`, `T2`, etc.): Syntactically simple but provides no structural information. The model cannot distinguish a package name token from a hostname token, which matters because BPE tokenisers split `EMAIL_01` into distinct subword tokens that preserve entity-type signal, while `T1` collapses to a single ambiguous token that the model frequently drops in paraphrase (observed in preliminary round-trip tests on the tokenize PoC at `8f04b25`: `EMAIL_01` survived verbatim in 97% of completions, vs an internal ad-hoc test run where `T1`-style tokens were paraphrased away or renumbered in >30% of outputs — confidence medium, formal A/B deferred per ADR-5 follow-up). Rejected on round-trip reliability. (See Appendix C §C-6 for the planned A/B benchmark.)

**Confidence**: Medium. The fundamental correctness of this approach is sound, but the optimal token grammar for each language is still being determined empirically.

**Pending A/B test**: Run 200 developer sessions with two token grammar variants:
- Variant A: current shape-preserving grammars (`@scope/internal-pkg-NN`, `host-NN.internal`)
- Variant B: classifier-prefixed opaque tokens (`PKG-a3f2`, `HOST-b9c1`) — short enough to be unlikely to break parsers, long enough to be unique

Measure: (1) round-trip detokenise success rate (token preserved verbatim by model), (2) developer-rated response quality on a 1–5 scale. If Variant B achieves equivalent round-trip success with higher developer rating, switch to Variant B. Decision expected Q3 2026.

---

## Appendix A: Follow-up Technical TODOs

The following items are tracked from commit `8f04b25` message and `docs/proxy/TODO.md`:

- Redis-backed `TokenVault` (interface ready, swap `InProcessTokenVault` → `RedisTokenVault`)
- SQL lane via `node-sql-parser`
- AST lane via `tree-sitter` (TS/JS/Py/Java)
- Dictionary hot-reload via file watcher / Redis pub-sub
- Vault `purgeExpired()` scheduler — method exists (`src/proxy/vault.ts:110-117`), not wired to `setInterval` in `startProxy`
- Token namespace collision protection (prefix `OMC_` + session nonce)
- Metrics: `tokenize_total`, `detokenize_total` by classifier
- Bypass workflow with JWT-scoped approval (P3)
- CCCD false-positive mitigation (structural validator — province-code allowlist from Thông tư 59/2021/TT-BCA Phụ lục + gender-century digit + year plausibility + contextual trigger regex). **Do not** describe this as a "checksum" — no public check-digit algorithm exists in Thông tư 59.
- Vietnamese NER (Presidio + underthesea sidecar)
- A/B test token grammar (ADR-5 confidence=medium): opaque UUID vs realistic placeholder on 200 dev sessions, measure round-trip success + dev-rated quality

---

## Appendix B: Quick Start

```bash
git fetch origin
git checkout claude/ai-proxy-security-HNLsW
npm install
npm run test:run  # should be 94/94

# Smoke-run the proxy:
export ANTHROPIC_API_KEY=sk-ant-...
export OMC_PROXY_CLIENT_TOKEN=$(openssl rand -hex 32)
npx tsx src/proxy/cli.ts start --port 11434
```

To test with the sample dictionary:

```bash
# Point the proxy at the sample dictionary
cat > ~/.config/omc/proxy.jsonc <<'EOF'
{
  // Load sample dictionary entries
  "dictionary": {
    "path": "./src/proxy/sample-dictionary.json"
  },
  // Change email policy to tokenize (default is redact)
  "dlp": {
    "patterns": [
      {
        "name": "email",
        "regex": "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
        "policy": "tokenize"
      }
    ]
  }
}
EOF

npx tsx src/proxy/cli.ts start --port 11434
```

Test a tokenise round-trip:

```bash
curl -s http://127.0.0.1:11434/v1/messages \
  -H "Authorization: Bearer $OMC_PROXY_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-haiku-20241022",
    "max_tokens": 100,
    "messages": [{
      "role": "user",
      "content": "Summarise the risk for alice@vng.vn using Project Bluefin."
    }]
  }'
# Response will contain EMAIL_01 and CODENAME_01 replaced with real values.
```

View today's audit log:

```bash
npx tsx src/proxy/cli.ts audit --from $(date +%Y-%m-%d)
```

---

## Appendix C: Security Review Backlog (pre-P2 blockers)

> **Status**: This appendix was added after a security-auditor pass on the first draft of
> this document (2026-04-23, session `bf745002`). Each item below is a **gap between what
> this document designs and what the shipped code at `8f04b25` actually implements**, or a
> point where the design needs stronger grounding before P2 work begins. Items C-1 through
> C-4 and C-7 through C-9 **must** be closed (or explicitly deferred with CISO sign-off)
> before the P2 milestone exits review. C-5 and C-6 are already referenced inline from
> §2.2 / R-2 and ADR-5 respectively.
>
> **How to work this list**: each entry states the gap, the recommended resolution, and
> a concrete artifact the reviewer should produce (code change, benchmark, policy memo).
> Owners and target dates are TBD at the time of writing and must be filled in when the
> backlog is triaged.

### C-1. Audit HMAC Chain — promote from P3 to P2-mandatory

**Gap**. §4.6 describes fsync-per-event audit logging and "HMAC chain (P3)" as an optional
hardening. Review finds this is insufficient for NĐ 13/2023 **Điều 27 khoản 1 điểm đ**,
which requires *integrity* of personal-data processing records — not only durability.
fsync guarantees the write survived a crash; it does not guarantee the record was not
altered after the fact by an actor with filesystem access (root, a compromised operator,
or a misconfigured backup rotator).

**Resolution**. Move HMAC chaining into P2 as a mandatory control and specify the
minimum viable form in the design:

```
h_0 = HMAC-SHA256(K_day, "omc-proxy-audit-genesis-" || iso_date)
h_n = HMAC-SHA256(K_day, h_{n-1} || canonical_json(event_n))
```

Requirements:
- `canonical_json` = JCS (RFC 8785) to eliminate field-ordering ambiguity.
- `K_day` rotated monthly via the same KMS that protects the vault KEK.
- A **daily anchor**: at 00:00 local, write `{date, last_hn, event_count}` to a
  WORM-mode object (S3 Object Lock in compliance mode, or a signed manifest in a
  separate append-only log) to bound tampering to at most one day.
- `omc audit verify --from <date>` CLI verb to re-compute the chain and compare to the
  anchor; exit non-zero on mismatch.

**Artifact**. ADR amendment (promote to P2), implementation in `src/proxy/audit.ts` (new
`hmacChain`/`verifyChain` functions), and a test vector fixture checked into
`tests/proxy/audit-chain.test.ts`.

### C-2. FPE — specify scheme, key management, and domain constraints

**Gap**. §4.3 and ADR-1 reference "FPE (planned P2)" for bank account and credit card
numbers without specifying the cryptographic scheme. This leaves the reader unable to
assess security or implementability.

**Resolution**. Pin the following before P2 entry:

- **Scheme**: FF3-1 per NIST SP 800-38G Rev.1 (2019). FF1 is acceptable but FF3-1 is
  simpler (fewer Feistel rounds, faster) and has the revised tweak size after the 2017
  cryptanalysis. **Do not** use the original FF3 (withdrawn).
- **Block cipher**: AES-256 (matches the vault KEK algorithm for operational uniformity).
- **Minimum domain size**: 10^6 (per NIST SP 800-38G guidance after the 2017 attacks).
  This **excludes** from FPE scope: 4-digit PINs, 6-digit OTPs, 3-digit province codes,
  and any identifier with fewer than 6 digits. Such values must be redacted or blocked,
  not tokenised.
- **Key management**: FPE key derived per-tenant from the KMS root via HKDF; rotation
  policy identical to the vault KEK (quarterly, with overlapping validity window for
  in-flight tokens).
- **In-scope formats for v1**: 16-digit PAN (credit card), 12-14 digit bank account, 11-
  to 13-digit MST. BHXH (10 digits) is in scope; CCCD (12 digits) is **not** — CCCD is
  tokenised, not FPE'd, because preserving the 12-digit space does not add any downstream
  validator value and leaks the last-10 digits as ciphertext in the token.

**Artifact**. ADR-6 (new, dedicated to FPE scheme choice) + `src/proxy/fpe.ts` stub
with scheme ID, domain check, and test vectors from NIST.

### C-3. Bypass JWT Workflow — full design & server-side enforcement

**Gap**. §4.5 describes the bypass token as `RS256, maxUses=1, 15-min TTL,
X-OMC-Bypass-Token`. No code exists at `8f04b25`. Several required elements are missing
from both design and planned implementation:

1. **Replay defense** beyond the claim: the `jti` must be checked against a Redis
   blacklist (set on first use, TTL = remaining token lifetime) so that `maxUses=1` is
   enforced even across proxy instances behind a load balancer.
2. **Revocation endpoint**: `POST /admin/bypass/revoke` authenticated via CISO-scoped
   admin credential (separate from the approval portal session), which writes the `jti`
   to the blacklist immediately, regardless of whether it has been used.
3. **Key rotation**: RS256 signing key rotated quarterly via JWKS with a 7-day overlap
   window so in-flight tokens remain valid across rotation.
4. **Approval portal MFA**: the portal that mints bypass tokens must require
   phishing-resistant MFA (WebAuthn/FIDO2 preferred; OIDC-backed MFA acceptable).
   Passwords + TOTP is not sufficient for a control that can bypass DLP.
5. **NEVER-for-SECRET must be server-enforced**, not advisory. On bypass resolution, the
   server re-runs the DLP classifier on the unmasked payload and rejects the request with
   `403 bypass_blocked_secret` if any classifier in the `SECRET.*` family fires. Audit
   row `bypass.action = "blocked_post_bypass"`.

**Resolution**. A dedicated ADR (ADR-7) covering the bypass lifecycle end-to-end; design
of the approval portal as a separate service (not embedded in the proxy); and the
server-side re-scan logic in `src/proxy/bypass.ts`.

**Artifact**. ADR-7 + threat model table for the bypass path + reference implementation
of the re-scan in `src/proxy/dlp.ts` (public API: `scanUnmasked(payload)` returning the
same `DlpMatch[]` as the masking path).

### C-4. Vietnamese NER — empirical gate before P2 commits

**Gap**. §4.2 / §6.1 commit to Presidio + underthesea as the Layer 3 NER detector in
P2. No precision/recall data exists for underthesea against the relevant corpus
(informal developer prompts mixing Vietnamese and English with code fragments).
Underthesea's published F1 scores are against VLSP 2016 and VLSP 2018 news corpora,
which have different lexical and structural characteristics.

**Resolution**. Before admitting the NER lane into the active detection path, require a
benchmark:

1. Collect a labelled dataset of ≥500 developer prompts (internal chat logs,
   sanitised), annotated for PERSON, ADDRESS, ORG entities in Vietnamese.
2. Hold out 20% as a test set. Measure precision and recall on the test set.
3. **Admission gate**: precision ≥ 0.85, recall ≥ 0.70. Below this, NER emits low-
   confidence matches (not enforced) and is used only as a hint for the regex/dict
   lanes.
4. Re-evaluate annually or after any underthesea model version bump.

If the gate fails, fall back options include: a larger model (VinAI PhoBERT-NER,
self-hosted), or restricting NER to names only with a hand-curated surname allowlist
from the General Statistics Office population registry.

**Artifact**. Benchmark harness in `benchmarks/ner-vn/` + results document +
go/no-go decision memo signed by security-reviewer before P2 implementation starts.

### C-5. CCCD Structural Validator (referenced from §2.2 and R-2)

**Gap**. The first draft of this document proposed a "Luhn-like checksum" for CCCD
12-digit regex false-positive mitigation. **This algorithm does not exist**: Thông tư
59/2021/TT-BCA and its Phụ lục define the structural layout of the CCCD number but do
not publish a check-digit algorithm, and the Bộ Công an has not released one. Any
"checksum" framing in internal documentation, tests, or code comments is factually
incorrect and must be removed or corrected.

**Resolution**. Replace the checksum proposal with a structural validator:

Structure (per Thông tư 59/2021/TT-BCA): `PPP G YY NNNNNN`
- `PPP` (digits 1–3): province code, one of 63 values in the Phụ lục allowlist.
- `G`   (digit 4): gender + century code; the combinatorial values determine the
                   allowed `YY` range (e.g., G=0 → male, 1900–1999; G=1 → female,
                   1900–1999; G=2 → male, 2000–2099; etc.).
- `YY`  (digits 5–6): last two digits of year of birth; must be consistent with G.
- `NNNNNN` (digits 7–12): sequence number within province/year/gender cohort; no
                          validation possible without a registry lookup.

Validator pseudocode:
```ts
function isPlausibleCCCD(s: string): boolean {
  if (!/^\d{12}$/.test(s)) return false;
  const province = Number(s.slice(0, 3));
  if (!PROVINCE_CODES_2021.has(province)) return false;
  const genderCentury = Number(s[3]);
  const yy = Number(s.slice(4, 6));
  const year = centuryFromGender(genderCentury) + yy;
  if (year < 1900 || year > new Date().getFullYear()) return false;
  return true;
}
```

Combine with a contextual trigger: only run the expensive validator when the 12-digit
candidate is within N tokens of a trigger phrase (`CCCD`, `CMND`, `căn cước`,
`số định danh`, `citizen id`). This bounds false-positive suppression cost while
keeping coverage on realistic prompts.

**Artifact**. `src/proxy/dlp-vn.ts` with `isPlausibleCCCD` + `PROVINCE_CODES_2021`
constant (63 entries) + unit tests using a fixture of 50 real-structured CCCDs (all
rejected must be explicitly justified) and 50 12-digit non-CCCDs (order IDs, phone
runs).

### C-6. Token grammar A/B test (referenced from ADR-5)

**Gap**. ADR-5 confidence is declared medium because the round-trip reliability claim
(`EMAIL_01` style beats `T1` style) is based on informal observation, not a controlled
benchmark.

**Resolution**. Run an A/B on at least 200 prompts sampled from the dev proxy corpus,
measuring:

- Round-trip success rate (token emitted identically in completion).
- Developer-rated response quality (blind 5-point Likert).

Gate: if `EMAIL_01` style does not beat `T1` style by ≥ 10 percentage points on round-
trip and is not worse on response quality, the ADR-5 direction can be reconsidered.

**Artifact**. `benchmarks/token-grammar-ab/` + results doc + ADR-5 status update.

### C-7. Data-subject rights — map Điều 14–17 to vault operations

**Gap**. NĐ 13/2023 Điều 14 (right to know), Điều 15 (right of access), Điều 16 (right
to rectification), and Điều 17 (right to erasure / object) apply to personal data held
in the token vault. The current design does not map these rights to concrete vault
operations or SLAs.

**Resolution**. Add a dedicated section (or subsection of §4.6) covering:

- **Right to know (Đ.14)**: enumerate the categories of personal data tokenised
  (email, phone, CCCD, bank, etc.). Link from the developer-facing proxy docs.
  Response SLA: **72 hours** per Điều 14 khoản 4.
- **Right of access (Đ.15)**: `omc vault lookup --subject <identifier>` CLI verb that
  returns all tokens currently mapped to a given plaintext (requires subject
  verification — CCCD + email confirmation). Audit every use.
- **Rectification (Đ.16)**: since tokens map by-value, rectification is a re-
  tokenisation of the corrected value; the old token is blacklisted but the
  plaintext-to-token mapping for the new value is a new entry.
- **Erasure (Đ.17)**: `omc vault purge --subject <identifier>` forces TTL-expiry of all
  mappings containing the subject's plaintext. Retention rules in Điều 37 (≥2 years
  for audit logs) continue to apply to the *audit trail* — which only contains
  HMAC-truncated hashes, not plaintext — so no conflict.

**Artifact**. New §4.7 "Data-subject rights (NĐ 13/2023 Đ.14–17)" + `src/proxy/
vault-rights.ts` CLI implementations.

### C-8. Threat model gaps

**Gap**. Three attack surfaces are not covered in §4.6 or elsewhere:

1. **Upstream-response DLP scan absent**. If Anthropic's response ever echoes something
   that was not in the request (e.g., hallucinated PII, prompt-injection leak), the
   proxy has no scrubber on the return path. SSE tokens are detokenised but nothing
   re-scans the final completion for new matches.
2. **Timing oracle on detection path**. The DLP matcher's per-classifier time varies
   with input content (regex backtracking, Aho-Corasick match counts). A hostile
   client probing the proxy may be able to infer whether a given string triggered a
   particular classifier by measuring request latency.
3. **Vault audit log side-channel**. The audit record currently logs the token (`EMAIL_01`)
   plus classifier name plus byte offsets. If an operator reviewing logs also has access
   to the vault, the log plus the vault = plaintext. The log format must emit only
   `sha256(value)[:8]` of the plaintext as the cross-reference handle, and the vault
   lookup must require a separate credential from the log reader.

**Resolution**.

1. Add a response-path DLP pass. Not full re-scan (latency prohibitive for streaming),
   but a classifier subset for high-risk categories (`SECRET.*`, `CCCD`, `BANK_ACCOUNT`)
   that runs on SSE chunks before forwarding to the client.
2. Add a latency-smoothing buffer on the mask path: measure the 99th-percentile
   matcher time over the last N requests per classifier, pad each response to that
   latency. Costs ≤10 ms p95; removes the timing oracle at the detection-decision
   boundary.
3. Change the audit log field from `token` to `tokenHashPrefix = sha256(plaintext)[:8]
   || "||" || classifier`. Separate the vault-reader credential from the log-reader
   credential (distinct IAM roles / Kubernetes service accounts).

**Artifact**. ADR addendum to ADR-1 covering the three controls + patches to
`src/proxy/audit.ts`, `src/proxy/dlp.ts`, `src/proxy/server.ts`.

### C-9. Code cross-check §2 pending

**Gap**. The security-auditor pass that produced this backlog was blocked from loading
source files in full (a Read-tool truncation issue). §2 ("Current state and
capabilities") therefore has not been independently verified against the shipped code
at commit `8f04b25`. The auditor flagged this explicitly.

**Resolution**. A separate reviewer pass must:

1. Load each `src/proxy/*.ts` file in full (or use file-reading via Bash as a
   workaround if the default Read path is truncated).
2. Verify that every capability listed in §2 matches a concrete code path (function
   or module reference by line number).
3. Flag any §2 claim that is aspirational rather than shipped.

Until C-9 closes, §2 should be read as "design intent of the shipped code" rather than
"verified shipped code".

**Artifact**. Annotated §2 with per-capability code line references, signed off by
reviewer in a commit message trailer.

### Summary table

| # | Topic | Blocker for P2? | Artifact owner (TBD) | Target |
|---|-------|-----------------|---------------------|--------|
| C-1 | HMAC audit chain | Yes (NĐ 13/2023 Đ.27) | security-reviewer | Before P2 kickoff |
| C-2 | FPE scheme spec | Yes | security-reviewer + backend | Before first FPE code commit |
| C-3 | Bypass JWT hardening | Yes | security-reviewer + platform | Before bypass code ships |
| C-4 | VN NER benchmark | Yes (precondition) | ML-ops + security-reviewer | Before NER lane enabled |
| C-5 | CCCD structural validator | Correctness fix (ship with P2) | backend | P2 sprint 1 |
| C-6 | Token grammar A/B | Confidence lift (non-blocker) | research | Opportunistic |
| C-7 | Data-subject rights | Yes (NĐ 13/2023 Đ.14–17) | DPO + backend | Before P2 GA |
| C-8 | Threat model gaps | Yes | security-reviewer + backend | Before P2 GA |
| C-9 | Code cross-check §2 | Yes (doc correctness) | reviewer | Before next PR on this doc |
