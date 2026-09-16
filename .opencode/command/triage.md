---
description: Attack-surface triage and threat modeling only (fast, no deep analysis). Outputs a partitioned function list, candidate source->sink chains, and saves reports/threat-model-<name>.md.
agent: re-triage
---

Binary to triage: $ARGUMENTS

If empty, ask for the binary path. Produce the full threat model + triage
report per your procedure and save it under reports/threat-model-<name>.md.
End with the partition map (entry points → function address lists) and
candidate source→sink chains for deep analysis.
