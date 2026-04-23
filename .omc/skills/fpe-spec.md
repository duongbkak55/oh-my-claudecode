---
name: FPE Scheme Spec (C-2)
description: Inject the agreed FPE scheme, domain constraints, and key management spec before any Format-Preserving Encryption code lands.
triggers: ["FPE", "FF3-1", "FF1", "format-preserving encryption", "Format Preserving"]
source: manual
---

## Rule

FPE scheme is **FF3-1** per **NIST SP 800-38G Rev.1 (2019)**. Not FF1. Never the original FF3 (withdrawn after the 2017 cryptanalysis).

docs/proxy/security-design.md **Appendix C-2**.

## Hard constraints

| Item | Value |
|------|-------|
| Scheme | FF3-1 (AES Feistel, revised tweak size) |
| Block cipher | AES-256 (matches vault KEK algorithm for operational uniformity) |
| Minimum domain size | **10^6** (per NIST SP 800-38G guidance after 2017 attacks) |
| Key derivation | HKDF from KMS root, per-tenant |
| Rotation | Quarterly, overlapping validity window for in-flight tokens |

## In-scope formats (v1)

- **16-digit PAN** (credit card) — Luhn checksum preserved by FF3-1 with a Luhn-aware character set
- **12–14 digit bank account**
- **11–13 digit MST** (Vietnam tax code)
- **10-digit BHXH** (social insurance)

## NOT in FPE scope

- **CCCD** (12 digits) — tokenise via vault instead. Preserving the 12-digit space adds zero validator value and leaks the last-10 digits as ciphertext in the token.
- **4-digit PIN** — domain 10^4 < 10^6, below NIST minimum.
- **6-digit OTP** — domain 10^6 is the floor; ephemeral so not worth FPE.
- **3-digit province code** — domain 10^3, way below minimum.

For anything below the domain floor: **redact** (policy=`redact`) or **block** (policy=`block`). Never FPE.

## Required artifacts (DoD for closing C-2)

- ADR-6 (dedicated FPE scheme choice).
- `src/proxy/fpe.ts` stub with:
  - Scheme ID string (e.g. `"ff3-1-aes256"`)
  - Domain size validator (throw on ciphertext < 10^6)
  - NIST test vectors from SP 800-38G Rev.1 Appendix in `tests/proxy/fpe-nist-vectors.test.ts`
- Key derivation via `crypto.hkdf` from Node stdlib (no third-party KDF).

## Do NOT

- Roll your own FPE. Use `@noble/ciphers` or audited equivalent; never hand-code the Feistel rounds.
- Ship FPE code without NIST test vectors in the test suite.
- Accept strings shorter than 6 characters as FPE input — hard-fail at the API boundary.
