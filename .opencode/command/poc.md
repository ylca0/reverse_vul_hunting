---
description: Forge a runnable PoC for a finding (by id in reports/, or pasted JSON) — boundary computation, trigger construction, execution with captured exit codes/sanitizer output, packaged under reports/poc/. Use after verification, or when you want hands-on proof.
agent: poc-forge
---

Finding to forge a PoC for: $ARGUMENTS

If a finding id is given, locate it in reports/ (analysis-*.md JSON blocks or
verifier outputs). If raw JSON is given, use it directly. If neither, ask.
Climb the ladder: P0 boundary computation → P1 malformed input → P2 crash /
sanitizer → P3 primitive demonstration. Harm-minimizing triggers only.
Produce the evidence package reports/poc/<finding-id>/ (input + compute.py +
run.sh + run.log) and output the PoC JSON verdict.
