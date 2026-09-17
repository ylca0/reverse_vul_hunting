---
description: Run the full binary vulnerability hunting pipeline (triage -> parallel partitioned analysis -> adversarial verification -> PoC forging -> merged report) on one or more target binaries. High-severity oriented: RCE, auth bypass, privilege escalation, data breach.
agent: vuln-orchestrator
---

Target binary/binaries: $ARGUMENTS

Run the complete vulnerability hunting pipeline on the given targets:

1. Dispatch re-triage per binary → threat model + entry-point partition map
   + candidate source→sink chains.
2. Split the partition map and dispatch vuln-analyst agents IN PARALLEL (one
   per entry-point partition, up to 4 per binary). Crown-jewel classes only.
3. Dispatch vuln-verifier agents IN PARALLEL for all medium+ findings
   (crown-jewel candidates first). Adversarial: kill mandate, cold start,
   empirical gate.
4. Dispatch poc-forge agents IN PARALLEL for every CONFIRMED (static) finding
   → evidence packages under reports/poc/.
5. Merge into reports/<binary-name>-<YYYYMMDD>.md with:
   - Executive summary (counts by verdict x severity)
   - Confirmed findings (dynamic, PoC-backed) — gold tier, link reports/poc/
   - Confirmed findings (static) — with explicit empirical-gate status
   - Unverified findings (explicitly marked)
   - Noted, not pursued (low-impact, one line each)
   - Refuted appendix (with killing citations)
   - Coverage statement (partitions, functions analyzed vs skipped)
   - Threat-model open questions

If $ARGUMENTS is empty, ask for the binary path. Do not proceed without a
real target file.

Workspace containment (enforce across all dispatched agents): targets are
analyzed in place from `./objects/`, intermediate artifacts go to `./tmp/`,
all documents and PoC evidence packages go to `./reports/`. No agent may
write to `/tmp`, `$TMPDIR`, macOS private temp paths (`/var/folders/...`), or
anywhere outside the project directory.
