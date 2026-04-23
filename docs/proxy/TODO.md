# AI Egress Proxy — TODO & Handover

Branch: `claude/ai-proxy-security-HNLsW`
Last pushed commit: `8f04b25`

## Done so far (3 commits on branch)

1. `1eb7045` — PoC: `src/proxy/{config,dlp,allowlist,audit,agent-loop,server,cli}.ts` + 41 tests.
2. `ab9ac90` — Applied 15 review fixes (auth bearer, SSE rolling-buffer vs split-secret, realpath symlink reject, HITL perms, backpressure, Zod upstream validate, fsync, HTTPS-only, error DLP-scan, XFF trust, etc.). Tests → 70.
3. `8f04b25` — P1 vault + dictionary lane: `vault.ts`, `dictionary.ts` (Aho-Corasick, no dep), `sample-dictionary.json`, `tokenize` policy, SSE detokenizer, system-prompt inject, round-trip. Tests → 94.

Run `npm test` to verify (should be 94/94 green, tsc clean).

## Pending (what I was working on when interrupted)

### B — Consolidated design doc
Write `docs/proxy/security-design.md` merging the 4 BA/SA reports I produced in the previous Claude session. Content exists only in that conversation transcript, NOT in files. Structure:

1. Executive summary (1 page)
2. Current state & capabilities (what the 3 commits ship)
3. BA analysis — PII masking/mapping
   - Stakeholders (dev, security, data owner, platform, auditor, CISO, DPO)
   - Use cases US-1..US-8 (refactor PII-safe, round-trip persona, quarterly egress review, declarative sensitivity, CCCD proof-of-non-egress, codename protection, approved bypass, audit-only canary)
   - FR-1..FR-12, NFR-1..NFR-8
   - Classification tiers PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED with VN-specific examples (CCCD, MST, BHXH, bank account)
   - Risk register R-1..R-10
   - Acceptance criteria AC-1..AC-7
4. SA architecture — PII layer
   - Layered detection (regex → dict → NER Presidio sidecar self-hosted)
   - Token vault: in-process (PoC) → Redis (prod) + envelope encryption (DEK/KEK + KMS)
   - Token format `EMAIL_01` per-conv + BPE paraphrase gotcha + system-prompt inject
   - Strategies mix: tokenize PII | FPE numeric | hash secrets | block credentials | pseudonymization
   - Bypass JWT 15min maxUses=1, never for `SECRET.*`
   - Audit HMAC + counter aggregation for NĐ 13/2023 proof
5. BA extension — source code DLP
   - US-9..US-15 (refactor with internal pkg safe, stack-trace triage, SQL review, dependency upgrade, codename brainstorm, dict self-service, compliance audit)
   - 12 new entity classes: INTERNAL_PACKAGE, CODENAME, PARTNER_NAME, INTERNAL_HOST, INTERNAL_CLASS_PATH, BRAND_VS_COMPETITOR, TICKET_REF, AUTHOR_TAG, DB_SCHEMA_IDENT, ML_MODEL_NAME, INTERNAL_API_ENDPOINT, FILE_PATH_INTERNAL
   - FR-13..FR-21 (shape-preserving tokenization, comment redaction, SQL parseable, stack-trace depth, path normalization, codename self-service, language-aware routing, anonymize-company mode, round-trip SLA)
   - Risks R-11..R-17
   - Compliance: Luật SHTT 2005 Đ.84 + Luật Cạnh tranh 2018 Đ.45 (trade secret protection as IP control)
6. SA extension — source code layer
   - 4-lane detector: regex + dict (Aho-Corasick) + AST (tree-sitter + node-sql-parser) + heuristic
   - Token grammar table (10 shapes preserving language syntax)
   - SQL pipeline: sniff → parse → walk AST → tokenize identifiers → re-serialize
   - Stack-trace: keep top-3 + bottom-3, collapse middle
   - Codename dict self-service: Postgres + Redis pub-sub hot reload + AC rebuild in worker thread
   - Defensive detokenize: system-prompt + vault-anchored
   - Perf: +30-50ms p95 → budget ≤130ms for code path
7. Migration plan
   - P1 (1-5) vault + PII — **DONE in 8f04b25**
   - P2 (6-10) NER + 4 code classes + self-service portal
   - P2.5 NEW (11-13) AST lane behind `OMC_PROXY_AST_DLP=1`
   - P3 (14-16) bypass + KMS + multi-tenant
8. ADRs (5 total)
   - ADR-1 Masking mode: layered (tokenize PII, FPE numeric, hash secrets, block creds)
   - ADR-2 Vault storage: Redis + envelope enc, reject SQLite + Skyflow cloud
   - ADR-3 Detection: hybrid regex+dict in-TS + Presidio NER sidecar
   - ADR-4 Code-aware: tree-sitter + node-sql-parser embedded, reject semgrep sidecar
   - ADR-5 Token grammar code: language-syntax-preserving, reject opaque UUID, reject realistic substitution

**How to resume**: ask Claude to "write docs/proxy/security-design.md combining BA+SA reports per docs/proxy/TODO.md outline" — Claude will regenerate the content from the outline above.

### E — PR
After `security-design.md` is committed:
```
gh pr create --base dev --title "feat(proxy): AI egress proxy with DLP + reversible tokenization" \
  --body-file <(...)  # include link to docs/proxy/security-design.md
```
Or via MCP `mcp__github__create_pull_request` — base branch likely `dev` based on `git log`.

## Follow-up technical TODOs (tracked in commit 8f04b25 message)

- Redis-backed TokenVault (interface ready, swap `InProcessTokenVault` → `RedisTokenVault`)
- SQL lane via `node-sql-parser`
- AST lane via `tree-sitter` (TS/JS/Py/Java)
- Dictionary hot-reload via file watcher / Redis pub-sub
- Vault `purgeExpired()` scheduler — method exists, not wired to `setInterval` in `startProxy`
- Token namespace collision protection (prefix `OMC_` + session nonce)
- Metrics: `tokenize_total`, `detokenize_total` by classifier
- Bypass workflow with JWT-scoped approval (P3)
- CCCD Luhn-like checksum to reduce false-positive (12-digit order IDs)
- Vietnamese NER (Presidio + underthesea sidecar)
- A/B test token grammar (ADR-5 confidence=medium): opaque UUID vs realistic placeholder on 200 dev sessions, measure round-trip success + dev-rated quality

## Quick start after pull

```bash
git fetch origin
git checkout claude/ai-proxy-security-HNLsW
npm install
npm run test:run  # should be 94/94
# smoke-run the proxy:
export ANTHROPIC_API_KEY=sk-ant-...
export OMC_PROXY_CLIENT_TOKEN=$(openssl rand -hex 32)
npx tsx src/proxy/cli.ts start --port 11434
```
