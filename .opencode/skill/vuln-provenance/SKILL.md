---
name: vuln-provenance
description: Evidence grading and adversarial verification rules for vulnerability findings — tool-proven vs derived vs model-asserted provenance levels, verification ladder, kill mandates, and the empirical gate that kills plausible-but-wrong findings. Use when producing, verifying, or merging findings so the report only claims what evidence supports.
---

# Vulnerability Provenance & Evidence Rules

A finding is worth exactly what its evidence is worth. Every claim in every
report carries a provenance level; the pipeline's job is to push claims up the
ladder or kill them.

## 1. Provenance levels

| Level | Meaning | Report treatment |
|---|---|---|
| **P1 tool-proven** | backed by captured tool output: idalib-cli decompile/disasm/xrefs text, a crash exit code from an executed PoC, sanitizer report, protocol response bytes | may be labeled CONFIRMED |
| **P2 derived** | logically derived from P1 artifacts (e.g. "buffer is 48 bytes" computed from two stack-slot offsets, "reachable from entry" from a caller chain) with the derivation shown | may be labeled CONFIRMED (static) |
| **P3 model-asserted** | plausible reasoning with no captured artifact behind it | always UNVERIFIED; a hypothesis, never a finding |

Model prose is analysis, not evidence. A final answer without tool citations
stays P3 no matter how confident it sounds. When merging, any finding whose
evidence chain does not end in P1/P2 gets demoted to the unverified section —
silently upgrading provenance is report fraud.

## 2. Verification ladder

Climb as far as possible; each level either promotes or kills the finding.

- **L1 static re-derivation (always)** — independently re-decompile the sink
  function and caller chain. Confirm: sink exists at the cited address, buffer
  size matches the stack layout (`// [xsp+..]` comments), no guard was missed.
- **L2 reachability proof** — walk from entry point to sink; every hop must
  preserve attacker data. Any hop that drops, transforms, or bounds the input
  kills the finding (quote the sanitizing line).
- **L3 dynamic PoC** — execute a crafted trigger when feasible (local binary
  or controlled test environment). A controlled crash / sanitizer report /
  observable effect promotes to CONFIRMED (dynamic). A negative dynamic result
  does NOT kill a solid static finding — record the caveat (mitigations, ASLR).
- **L4 impact assessment** — if confirmed: what primitive? controlled PC,
  arbitrary write, info leak, auth bypass with concrete impact. Label
  theoretical exploitability as theoretical.

## 3. Adversarial rules (kill mandates)

- The verifier's loyalty is to TRUTH, not the analyst. Default stance: the
  finding is WRONG until evidence says otherwise.
- **Kill mandate**: actively hunt for the missing bound check, the sanitizing
  hop, the fortify bound that saves the sink. Finding nothing to kill is the
  exception, not the default.
- **Cold start**: verify from the binary alone. Do not read the analyst's
  narrative before re-deriving the facts yourself — anchoring makes reviewers
  rubber-stamp. Read the finding JSON's addresses only, then look at the code.
- **Blunt verdicts**: never soften REFUTED into UNVERIFIABLE to be polite.
  REFUTED findings stay in the report appendix with the killing citation —
  refutation evidence is valuable.

## 4. The empirical gate

Ten reviewers unanimously endorsing a non-existent bug, killed by one test —
that failure mode is real and documented. Rule: **no critical/high finding
reaches the final report's confirmed section on static reasoning alone if any
empirical check is feasible.** The empirical check is the cheapest thing that
could kill the claim:

- run the binary under the trigger (exit code / signal / sanitizer)
- craft the minimal protocol/file input and observe the response
- compute the exact boundary value with a script (not in your head)

If no empirical check is feasible (no local run, live service only), mark
explicitly: `empirical gate: skipped (unavailable)` — allowed for
UNVERIFIABLE, forbidden for CONFIRMED (dynamic).

## 5. Operator checklist before trusting a finding

1. Is there an evidence item (tool output, command result, crash log)?
2. Does the finding cite it by address/command?
3. Was the claim re-derived independently, not inherited?
4. Did any kill attempt succeed or fail, and is that recorded?
5. Is the provenance level stated and honest?

If any answer is no, the finding stays unverified.
