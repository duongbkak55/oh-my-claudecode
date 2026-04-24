---
name: CCCD Structural Validator
description: Inject the agreed structural-validator spec for Vietnamese CCCD numbers. Use when touching DLP code that handles the cccd_vn classifier or writing docs that mention CCCD false-positive mitigation.
triggers: ["CCCD", "cccd_vn", "căn cước", "số định danh", "citizen id", "Thông tư 59"]
source: manual
---

## Hard rule

**Thông tư 59/2021/TT-BCA does NOT publish a public check-digit algorithm for CCCD.** Never write or commit code, doc, test, or comment that calls the CCCD validator a "Luhn checksum", "check digit", or equivalent. The audit flagged this as a factual error (docs/proxy/security-design.md Appendix C-5).

## What to implement instead

A structural validator combining four signals:

1. **Province code allowlist** — 63 values from Phụ lục Thông tư 59/2021/TT-BCA (first 3 digits).
2. **Gender-century digit consistency** — digit 4 encodes gender + century; must be consistent with the year in digits 5–6.
3. **Year plausibility** — derived year ≥ 1900 and ≤ current year.
4. **Contextual trigger regex** — only run the validator on 12-digit candidates within N tokens of a trigger phrase (`CCCD|CMND|căn cước|số định danh|citizen id`) to bound false-positive suppression cost.

## Reference pseudocode

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

Structure reminder: `PPP G YY NNNNNN`
- `PPP` (1–3): province code (allowlist check)
- `G` (4): gender + century (G=0 → male 1900–1999; G=1 → female 1900–1999; G=2 → male 2000–2099; etc.)
- `YY` (5–6): last two digits of year of birth
- `NNNNNN` (7–12): sequence — no validation possible without registry lookup

## Artifacts to produce

- `src/proxy/dlp-vn.ts` with `isPlausibleCCCD` + `PROVINCE_CODES_2021` constant (63 entries).
- Unit tests with ≥50 real-structured CCCDs + ≥50 12-digit non-CCCDs (order IDs, phone runs).
- Remove any "Luhn" framing from comments, test names, and TODO notes if encountered.
