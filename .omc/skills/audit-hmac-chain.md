---
name: Audit HMAC Chain Spec (C-1)
description: Inject the minimum-viable HMAC chain spec for tamper-evident audit logging before anyone writes fsync-only audit code and calls it "integrity".
triggers: ["audit chain", "audit HMAC", "audit integrity", "tamper-evident", "audit log integrity", "Điều 27"]
source: manual
---

## Rule

fsync alone is **NOT integrity**. It's durability (survives crash). An adversary with filesystem access (root, compromised operator, misconfigured backup rotator) can rewrite past audit events after the fact. NĐ 13/2023 **Điều 27 khoản 1 điểm đ** requires integrity of processing records.

This is docs/proxy/security-design.md **Appendix C-1**: promoted from P3 to P2-mandatory.

## Minimum viable chain

```
h_0 = HMAC-SHA256(K_day, "omc-proxy-audit-genesis-" || iso_date)
h_n = HMAC-SHA256(K_day, h_{n-1} || canonical_json(event_n))
```

- `canonical_json` = **JCS (RFC 8785)** — eliminates field-ordering ambiguity
- `K_day` rotated **monthly** via the same KMS that protects the vault KEK
- **Daily anchor**: at 00:00 local, write `{date, last_hn, event_count}` to a WORM store:
  - S3 Object Lock in compliance mode, OR
  - Signed manifest in a separate append-only log
  
  This bounds tampering to at most one day.

## CLI verb to implement

```
omc audit verify --from <date>
```

Re-computes the chain and compares to the daily anchor. Exit non-zero on mismatch. Must run in CI on a daily cadence.

## Required artifacts (DoD for closing C-1)

- ADR amendment promoting C-1 from P3 to P2.
- `src/proxy/audit.ts`: new `hmacChain` / `verifyChain` helpers.
- `tests/proxy/audit-chain.test.ts`: test vectors (genesis, append, verify OK, verify FAIL on tampered event).
- CLI subcommand `omc audit verify` in `src/proxy/cli.ts`.

## Do NOT

- Ship `audit.ts` changes that add fields to the event but keep durability-only persistence and call it "integrity".
- Use JSON.stringify for canonicalisation (field order unstable, whitespace drift).
- Derive K_day via anything other than HKDF from the KMS KEK.
