# Reverse Vulnerability Hunting

Multi-agent binary vulnerability hunting built on opencode + IDA Pro 9.1
(`idalib-cli`). Modeled on Project Naptime/Big Sleep and Project Ire
methodology, hardened with adversarial-verification and evidence-provenance
practices (Refute-or-Promote, T3MP3ST provenance discipline).

## Mission

High-severity or nothing: RCE, auth bypass/越权, privilege escalation, data
breach. Every confirmed finding ships with a replayable PoC evidence package
— model assertions are never evidence.

## Architecture

```
/vulnhunt <binary>          (user)
    │
    ▼
vuln-orchestrator           pipeline planning & merging
    ├─► re-triage           attack surface -> threat model + partition map
    ├─► vuln-analyst xN     PARALLEL, one per entry-point partition
    │                       decompile + pattern audit -> finding JSON
    ├─► vuln-verifier xN    PARALLEL adversarial verification (kill mandate,
    │                       cold start, empirical gate)
    ├─► poc-forge xN        PARALLEL PoC construction -> reports/poc/<id>/
    ▼
reports/<binary>-<date>.md
```

Agents live in `.opencode/agent/`, the knowledge base in
`.opencode/skill/`, pipeline entry points in `.opencode/command/`.

## Commands

- `/vulnhunt <binary>` — full pipeline (threat model → parallel partitioned
  analysis → verification → PoC forging → report)
- `/triage <binary>` — threat model + attack-surface triage only
- `/verify-finding <id|JSON>` — adversarial re-verification of one finding
- `/poc <id|JSON>` — forge a runnable PoC evidence package for one finding

## Knowledge base (skills)

- `vuln-patterns` — memory-safety + logic bug catalog with IDA pseudocode
  signatures, severity matrix, and false-positive traps
- `binary-threat-model` — crown-jewel impact classes, entry-point partition
  maps, function card tags (`SRC_*`/`SINK_*`/`BOUNDS_*`) for chain discovery
- `vuln-provenance` — evidence ladder P1 tool-proven / P2 derived / P3
  model-asserted, verification ladder L1–L4, kill mandates, empirical gate
- `poc-recipes` — PoC ladder P0–P3 and per-class trigger recipes (harm
  minimizing)

Skills auto-load for the agents that reference them; they are the single
place to extend domain knowledge.

## Tools

- `idalib-cli -d <bin> <cmd>` — all RE operations (stateless, JSON out).
  Prefer `batch` for multi-op; use `parallel` for multi-binary sweeps.
- One IDB per binary at a time; agents coordinate through IDB
  comments/bookmarks (persisted annotations).
- PoC execution: local binaries and localhost-only protocol targets;
  `reports/poc/<id>/` holds inputs, compute scripts, run logs.

## Report conventions

- Findings use IDs `F-001`, `F-002`, ... (globally unique across partitions).
- Every finding must carry: CWE, crown-jewel class, address, sink, source,
  data-flow path, evidence citations with provenance level, trigger idea.
- Verdicts: CONFIRMED (dynamic, PoC-backed) / CONFIRMED (static) /
  REFUTED / UNVERIFIABLE. Refuted findings stay in the report appendix —
  refutation evidence is valuable.
- Evidence honesty: claims backed only by model reasoning (P3) are demoted
  to unverified, never presented as findings.
- Coverage honesty: analysts state which partitions and functions were
  analyzed and which skipped.

## Adding patterns

Extend `.opencode/skill/vuln-patterns/SKILL.md` — one section per pattern:
Hex-Rays signature, key questions, severity logic. New threat-model concepts
go to `binary-threat-model`, verification rules to `vuln-provenance`, PoC
techniques to `poc-recipes`. The skills auto-load for analyst/verifier/forge
agents.
