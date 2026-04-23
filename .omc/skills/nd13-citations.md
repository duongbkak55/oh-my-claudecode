---
name: NĐ 13/2023 Citation Table
description: Map proxy controls to specific Điều (articles) of Nghị định 13/2023/NĐ-CP. Use when writing docs, audit messages, or comments about data protection compliance to avoid the audit finding that generic "NĐ 13/2023" references are non-compliant.
triggers: ["NĐ 13", "Nghị định 13", "data residency", "PII egress", "personal data", "DPO", "data protection", "cross-border transfer", "data subject"]
source: manual
---

## Rule

**Never cite "NĐ 13/2023" generically.** Every reference must name the specific `Điều` (article). The auditor flagged generic citations as non-compliant (docs/proxy/security-design.md Appendix C-8).

## Article → control mapping (use this table)

| Điều | Topic | Applies to (in this codebase) |
|------|-------|-------------------------------|
| **Điều 14** | Right to know — categories of personal data being processed. 72h response SLA per khoản 4. | Developer-facing proxy docs must enumerate tokenised categories (email, phone, CCCD, bank, etc.). Appendix C-7. |
| **Điều 15** | Right of access — data subject can request their data. | `omc vault lookup --subject <id>` CLI verb (planned). Audit every use. |
| **Điều 16** | Right to rectification — correct inaccurate data. | Re-tokenise new value; blacklist old token. |
| **Điều 17** | Right to erasure / object. | `omc vault purge --subject <id>` — TTL-expire all mappings. |
| **Điều 22** | Cross-border data transfer prohibition without conditions. | Motivates the proxy itself — proof-of-non-egress audit trail for CCCD, phone, bank. §3.6 R-5. |
| **Điều 25** | Mandatory DPIA for Cross-Border Transfer (DPIA-CBT), filed with A05/Bộ Công an. | Why we reject Skyflow and any cloud tokenisation vault (ADR-2). |
| **Điều 26** | Incident notification to A05 within 60 days of any data breach affecting transferred data. | Same as Điều 25 — rejection reason for foreign-hosted vaults. |
| **Điều 27 khoản 1 điểm đ** | Integrity of personal-data processing records. | Justifies HMAC audit chain promotion from P3 to P2-mandatory. Fsync is durability, NOT integrity. Appendix C-1. |
| **Điều 37** | Log retention ≥ 2 years. | Audit log rotation + archive policy. |

## Common mistakes to avoid

- "NĐ 13/2023 requires X" → say "NĐ 13/2023 Điều NN requires X"
- "NĐ 13/2023 Art. 22" → use Vietnamese `Điều` for Vietnamese law (English translation OK in parenthesis)
- Citing Điều 22 for integrity requirements — wrong, use Điều 27.
- Citing Điều 27 for cross-border transfer — wrong, use Điều 22 / 25 / 26.

## When in doubt

Open `docs/proxy/security-design.md` Appendix C section C-1/C-7/C-8 and look at how citations are worded. Match that style.
