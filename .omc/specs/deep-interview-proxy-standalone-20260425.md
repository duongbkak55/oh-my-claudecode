# Spec: Standalone OMC AI Egress Proxy (Split-Repo Approach)
status: validated (user confirmed defaults 2026-04-25)
created: 2026-04-25
revised: 2026-04-25 (direction change: workspaces → split repo)
phases: 0 → A → B → C → D (sequential; intra-phase parallel where independent)

## Goal
Tách `src/proxy/` từ `oh-my-claudecode` thành **repository GitHub mới độc lập**, thêm auth lane (bearer token + rotation + per-token rate-limit) và xuất bản deployment artifacts (Docker + caddy + systemd) để deploy như AI egress proxy độc lập, đáp ứng yêu cầu gốc: AI proxy nội bộ → internet, không lộ source code.

## Non-goals
- Không đổi DLP behavior (regex/dictionary/SQL/AST lanes giữ nguyên semantics).
- Không break Claude Code plugin install (`oh-my-claude-sisyphus@4.9.3` vẫn publish bình thường sau khi proxy được tách).
- Không OAuth/OIDC, không mTLS, không K8s manifests, không native HTTPS, không admin UI vòng này.

## Resolved decisions (user confirmed defaults)
- **D1 — Repo**: name=`omc-ai-proxy`, owner=`duongbkak55`, visibility=`public`. Package name `@omc-ai/proxy` (scope public, available trên npm).
- **D2 — History**: `git filter-repo` extract `src/proxy/` (giữ commits từ PR #1, #3, #5, #7).
- **D3 — `oh-my-claudecode`**: clean break — `git rm -r src/proxy/` sau khi repo mới ổn.
- **D4 — Helpers**: vendor inline copy 3 file (`atomic-write.ts`, `ssrf-guard.ts`, `jsonc.ts`), tổng 481 LOC.

## Constraints
- C1: Existing publish surface `oh-my-claude-sisyphus@4.9.3` không break.
- C2: Plugin install (`.claude-plugin/`, `bridge/cli.cjs`) vẫn hoạt động sau khi proxy bị remove.
- C3: filter-repo phải chạy trên CLONE (không phải repo gốc) để tránh hỏng remote.
- C4: Auth lane backward compatible — `auth.enabled = false` mặc định.
- C5: Rollback: mọi destructive action có rollback path documented (revert commit, force-push backup branch, etc.).

## Architecture Decisions

### AD-1: Repository topology
Hai repo riêng biệt sau split:
```
github.com/<owner>/oh-my-claudecode      # plugin layer, src/proxy/ removed
github.com/<owner>/<NEW_REPO_NAME>       # standalone proxy
```
Không cross-dep ở runtime: `oh-my-claudecode` không import `@<scope>/proxy`. Người dùng muốn dùng cả hai install cả hai.

### AD-2: New repo structure
```
<new-repo>/
├── package.json              # name "@<scope>/proxy", bin omc-proxy
├── tsconfig.json
├── vitest.config.ts
├── eslint.config.js
├── .github/workflows/ci.yml  # test + build + publish dry-run
├── README.md
├── LICENSE                   # MIT (match plugin)
├── src/
│   ├── index.ts              # public API export
│   ├── server.ts             # (moved from oh-my-claudecode)
│   ├── cli.ts
│   ├── config.ts
│   ├── dlp.ts
│   ├── allowlist.ts
│   ├── audit.ts
│   ├── vault.ts
│   ├── dictionary.ts
│   ├── sql-lane.ts
│   ├── ast-lane.ts
│   ├── agent-loop.ts
│   ├── auth.ts               # NEW (Phase B)
│   ├── lib/                  # vendored helpers
│   │   ├── atomic-write.ts   # vendored from oh-my-claudecode/src/lib/
│   │   ├── ssrf-guard.ts     # vendored from oh-my-claudecode/src/utils/
│   │   └── jsonc.ts          # vendored from oh-my-claudecode/src/utils/
│   └── __tests__/...
├── deploy/
│   ├── Dockerfile
│   ├── compose.yml
│   ├── Caddyfile
│   ├── systemd/omc-proxy.service
│   ├── sample-config.jsonc
│   └── README.md
└── docs/
    ├── security-design.md    # vendored from oh-my-claudecode/docs/proxy/
    └── auth.md               # NEW (Phase B)
```

### AD-3: Auth lane (Phase B) — bearer token + rotation + per-token quota
(Same as previous spec — schema, sha256 hash storage, timing-safe compare, token bucket rate-limit, CLI `omc-proxy auth issue|list|revoke|rotate`, default disabled.)

### AD-4: Pipeline order trong server.ts (Phase B)
1. Parse headers + body
2. **NEW**: `auth.validateRequest()` → 401 nếu fail
3. **NEW**: `rateLimiter.check(tokenId)` → 429 nếu vượt
4. Existing: `scanRequestForBannedTools`, `validateUpstreamUrl`
5. Existing: `redactAnthropicRequest` (DLP: AST → SQL → dictionary → regex)
6. Existing: forward upstream, apply SSE detokenization
7. Audit event includes `auth.tokenId`, không log plaintext.

### AD-5: Deployment artifacts (Phase C)
- Dockerfile multi-stage: `node:20-alpine` (builder) → `gcr.io/distroless/nodejs20` (runtime)
- compose.yml: 2 services `omc-proxy` + `caddy` với network bridge
- Caddyfile: auto Let's Encrypt + reverse_proxy → proxy:11434, có comment cho bring-your-own-cert
- systemd unit: hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`)
- README.md cover 3 modes: Docker compose, systemd + caddy, manual binary

### AD-6: Test strategy
- Unit: `src/__tests__/auth.test.ts`, `lib.test.ts` (vendored helpers)
- Integration: `__tests__/server-auth.test.ts`
- Existing tests phải pass nguyên (especially ast-lane, sql-lane, dlp, agent-loop)
- CI: GitHub Actions trên repo mới chạy `npm test` + `tsc --noEmit` + `npm run build`

### AD-7: Publish flow
- Repo mới: `npm publish` qua GitHub Actions, trigger từ git tag `v0.1.0`
- License MIT, README, CHANGELOG.md scaffold
- Không publish vòng đầu — chỉ scaffold; user quyết định khi nào release

## Phase 0 — Setup (gated on D1-D4)
0.1. User confirm D1-D4.
0.2. Tạo backup branch `archive/proxy-pre-split` trên oh-my-claudecode để rollback an toàn.
0.3. Clone `oh-my-claudecode` ra `/tmp/proxy-extract/` để filter-repo (KHÔNG đụng repo gốc).
0.4. Verify `git filter-repo` đã cài (`pip install git-filter-repo` nếu chưa).

## Phase A — Extract proxy → new repo
A1. Trong `/tmp/proxy-extract/`: `git filter-repo --path src/proxy/ --path-rename src/proxy/:src/`
A2. Verify history clean: `git log --oneline | wc -l` ≥ 10 commits liên quan proxy.
A3. Vendor 3 helpers: copy `oh-my-claudecode/src/lib/atomic-write.ts` → `lib/atomic-write.ts`, tương tự ssrf-guard, jsonc. Update relative imports trong proxy files.
A4. Tạo skeleton: `package.json` (name `@<scope>/proxy`, deps trừu xuất), `tsconfig.json`, `vitest.config.ts`, `eslint.config.js`, `LICENSE`, `README.md`, `.gitignore`, `.github/workflows/ci.yml`.
A5. Move `oh-my-claudecode/docs/proxy/security-design.md` + TODO.md → `docs/`.
A6. Run `npm install` + `npx vitest run` trong repo mới — pass full suite.
A7. `gh repo create <owner>/<NAME> --public --source=. --remote=origin` (irreversible — gated).
A8. `git push -u origin main`.
A9. Verify CI green trên GitHub Actions.
A10. Tag `v0.1.0-rc1` (chưa publish).

## Phase B — Auth lane (trong repo mới)
B1. `src/auth.ts`: AuthConfig Zod schema, hashToken, compareToken (timing-safe), RateLimiter (token bucket), AuthGate.validateRequest.
B2. Update `src/config.ts`: add `auth` section.
B3. Wire vào `src/server.ts` theo AD-4.
B4. Update `src/cli.ts`: thêm `auth issue|list|revoke|rotate`.
B5. Tests: `__tests__/auth.test.ts` + `__tests__/server-auth.test.ts`.
B6. Update `audit.ts`: thêm `auth.tokenId` field.
B7. `docs/auth.md`: design + usage examples.
B8. Run full test suite + `tsc --noEmit`.
B9. PR #1 trên repo mới: `feat: add auth lane with bearer tokens, rotation, rate-limit`.

## Phase C — Deployment artifacts
C1. `deploy/Dockerfile` (multi-stage, distroless).
C2. `deploy/compose.yml` (proxy + caddy services).
C3. `deploy/Caddyfile` (auto-HTTPS + reverse_proxy).
C4. `deploy/systemd/omc-proxy.service` với hardening.
C5. `deploy/sample-config.jsonc` (auth.enabled = true, 1 token mẫu).
C6. `deploy/README.md` (3 modes, env vars, troubleshoot).
C7. Verify `docker build` success (skip nếu env không có docker).
C8. PR #2 trên repo mới: `chore: add deployment artifacts`.

## Phase D — Cleanup oh-my-claudecode + final docs
D1. Trong `oh-my-claudecode` (repo gốc):
  - `git rm -r src/proxy/` (theo D3=a)
  - Update root `README.md`: thêm section "Standalone Proxy" với link đến repo mới
  - Update `docs/PROJECT-OVERVIEW.md` § proxy: chuyển thành reference link
  - `git rm -r docs/proxy/` (đã move sang repo mới)
  - Verify build/test root vẫn pass (proxy không có upstream import nên an toàn)
D2. PR trên `oh-my-claudecode`: `refactor: extract proxy to standalone repo <NEW_REPO>`.
D3. Sau merge: tag `oh-my-claudecode@4.10.0` (minor bump vì proxy bị remove).
D4. Repo mới: README pointer ngược về `oh-my-claudecode` cho plugin layer.

## Verification Gates
- G0 (after Phase 0): backup branch tồn tại, clone OK, filter-repo cài đặt OK.
- G1 (after Phase A): repo mới có CI green, tests pass, build success.
- G2 (after Phase B): G1 + auth tests 100% coverage + integration pass.
- G3 (after Phase C): G2 + Dockerfile build (nếu có docker).
- G4 (after Phase D): `oh-my-claudecode` post-removal vẫn build + test pass + plugin install OK qua `npm pack`.

## Out of scope (explicit)
- OAuth/OIDC, mTLS, K8s, multi-region HA, native HTTPS, admin UI, rate-limit per-IP, npm publish v0.1.0 (chỉ scaffold).

## Risk Register
- R1 (HIGH): filter-repo sai → mất history. Mitigate: chạy trên clone, backup branch.
- R2 (HIGH): `git rm src/proxy/` ở oh-my-claudecode trước khi repo mới ổn → temporary gap. Mitigate: D1 chỉ làm SAU khi G3 pass trên repo mới.
- R3 (MED): Helper duplicate → divergence theo thời gian. Mitigate: documented trong README repo mới + CHANGELOG note.
- R4 (HIGH): `gh repo create` + push không reverse được dễ. Mitigate: Phase 0 gate trên D1 user confirm.
- R5 (LOW): Rate-limit in-memory không scale horizontal. Mitigate: documented limitation.
- R6 (MED): Existing PR labels/issues không transfer. Mitigate: doc note, không transfer (out of scope).

## Phase parallelism
- Phase 0: sequential.
- Phase A: A1→A2→A3→A4 sequential. A5 song song A4. A6 depends A1-A5. A7-A10 sequential cuối.
- Phase B: B1, B2, B6 song song. B3 depends B1+B2. B4 depends B1+B2. B5 depends B3+B4. B7 song song B5. B8 depends all. B9 cuối.
- Phase C: C1-C6 song song. C7 depends all. C8 cuối.
- Phase D: D1.* sequential. D2-D4 cuối.

## Stop conditions
- Stop nếu G0 fail → report blocker.
- Stop nếu G1 fail 2 lần liên tiếp → có thể history corrupt từ filter-repo, escalate.
- Stop nếu G4 fail → DỪNG TRƯỚC khi force-push oh-my-claudecode main, rollback Phase D.
