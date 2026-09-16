---
description: Re-verify a specific finding (by id in reports/analysis-*.md, or pasted JSON) with the independent verifier — adversarial kill mandate, cold start, empirical gate. Use to challenge a finding you doubt.
agent: vuln-verifier
---

Finding to verify: $ARGUMENTS

If a finding id is given, locate it in reports/analysis-*.md. If raw JSON is
given, use it directly. If neither, ask. Run the full verification ladder
(L1 static re-derivation → L2 reachability → L3 dynamic PoC → L4 empirical
gate + impact). Build the PoC evidence package if you reach L3. Output the
verdict JSON (with provenance level and kill attempts) plus a human-readable
explanation.
