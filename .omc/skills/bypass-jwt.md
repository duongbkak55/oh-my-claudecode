---
name: Bypass JWT Hardening (C-3)
description: Inject the required hardening for the DLP bypass workflow before anyone ships a bypass token endpoint. Advisory-only NEVER-for-SECRET is non-compliant — this is docs/proxy/security-design.md Appendix C-3.
triggers: ["bypass", "X-OMC-Bypass-Token", "bypass JWT", "bypass workflow", "DLP bypass"]
source: manual
---

## Rule

The current design (`RS256, maxUses=1, 15-min TTL, X-OMC-Bypass-Token`) is **not enough**. Five hardening items MUST ship with any bypass code, and CISO sign-off is required before merge.

## Required controls (all must be implemented)

### 1. Replay defense via jti blacklist
- `jti` claim (UUID v4) checked against Redis blacklist (SET on first use, TTL = remaining token lifetime)
- Enforces `maxUses=1` even across proxy instances behind a load balancer
- No in-memory-only enforcement

### 2. Revocation endpoint
```
POST /admin/bypass/revoke
Authorization: CISO-scoped admin credential (separate from approval portal session)
Body: { jti: "<uuid>" }
```
- Writes `jti` to blacklist immediately, regardless of whether it has been used.

### 3. Key rotation via JWKS
- RS256 signing key rotated **quarterly**
- 7-day overlap window so in-flight tokens survive rotation
- JWKS endpoint must serve both keys during overlap

### 4. Approval portal MFA
- Phishing-resistant MFA **required** for minting bypass tokens
- **WebAuthn / FIDO2 preferred**
- OIDC-backed MFA acceptable
- Password + TOTP is **not sufficient** — TOTP is phishable

### 5. NEVER-for-SECRET — server-enforced
Advisory-only is non-compliant. Server-side re-scan:

```ts
// On bypass resolution (after token validates):
const rescan = await dlp.scanUnmasked(originalPayload);
const hasSecret = rescan.matches.some(m => /^SECRET\./i.test(m.classifier));
if (hasSecret) {
  audit({ bypass: { action: "blocked_post_bypass", jti, classifiers: rescan.matches.map(m => m.classifier) } });
  return res.status(403).json({ error: "bypass_blocked_secret" });
}
```

## Required artifacts (DoD for closing C-3)

- **ADR-7** — bypass lifecycle end-to-end
- Threat model table for the bypass path
- `src/proxy/bypass.ts` — implementation
- `src/proxy/dlp.ts` — new public `scanUnmasked(payload): DlpMatch[]`
- Integration tests covering: valid token+no-secret = pass, valid token+SECRET = blocked, replayed jti = 403, revoked jti = 403, expired (15min+1s) = 403, wrong MFA level = no token minted.
- CISO sign-off trailer in the commit message

## Do NOT

- Ship bypass code without all five controls.
- Embed the approval portal inside the proxy service — it's a separate trust boundary.
- Accept a bypass token in the same header as the client token (mix-up confusion).
- Cache bypass decisions across requests.
