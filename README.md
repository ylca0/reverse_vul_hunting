# Reverse Vulnerability Hunting

Multi-agent binary vulnerability hunting built on [opencode](https://opencode.ai) + IDA Pro 9.1 (`idalib-cli`).

**High-severity or nothing.** The pipeline hunts four crown-jewel outcomes only — RCE, auth bypass, privilege escalation, data breach — and every confirmed finding ships with a replayable PoC evidence package. Model assertions are never evidence.

Methodology lineage: [Project Naptime / Big Sleep](https://googleprojectzero.blogspot.com/2024/06/project-naptime.html) (Google Project Zero) · [Project Ire](https://www.microsoft.com/en-us/research/blog/project-ire-autonomously-identifies-malware-at-scale/) (Microsoft) · [Refute-or-Promote](https://arxiv.org/abs/2604.19049) (adversarial verification) · [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) (provenance discipline).

> 中文版本：[README.zh-CN.md](README.zh-CN.md)

## Why

LLM-assisted vulnerability discovery has a precision crisis: plausible-but-wrong findings overwhelm real ones. This project attacks that with three design commitments:

1. **Speed** — work is partitioned by entry point and dispatched to parallel subagents; verification and PoC forging also run in parallel.
2. **Depth** — cheap triage up front, frontier-model reasoning where it matters: decompilation auditing, adversarial verification, PoC construction.
3. **Verdicts, not vibes** — every claim carries a provenance level; a finding is only as strong as its tool output. Refuted findings stay in the report because refutation evidence is valuable.

## Architecture

```
/vulnhunt <binary>          (user)
    │
    ▼
vuln-orchestrator           pipeline planning & merging
    ├─► re-triage           attack surface -> threat model + partition map
    ├─► vuln-analyst xN     PARALLEL, one per entry-point partition
    │                       decompile + pattern audit -> finding JSON
    ├─► vuln-verifier xN    PARALLEL adversarial verification
    │                       (kill mandate, cold start, empirical gate)
    ├─► poc-forge xN        PARALLEL PoC construction -> reports/poc/<id>/
    ▼
reports/<binary>-<date>.md
```

Agents live in `.opencode/agent/`, the knowledge base in `.opencode/skill/`, pipeline entry points in `.opencode/command/`.

## Commands

| Command | What it does |
|---|---|
| `/vulnhunt <binary>` | Full pipeline: threat model → parallel partitioned analysis → adversarial verification → PoC forging → merged report |
| `/triage <binary>` | Attack-surface triage + threat model only (fast) |
| `/verify-finding <id\|JSON>` | Adversarial re-verification of one finding |
| `/poc <id\|JSON>` | Forge a runnable PoC evidence package for one finding |

## Knowledge base (skills)

Skills are the single place domain knowledge is sedimented; they auto-load for the agents that reference them.

| Skill | Contents |
|---|---|
| `vuln-patterns` | Memory-safety + logic bug catalog: IDA pseudocode signatures, severity matrix, false-positive traps |
| `binary-threat-model` | Crown-jewel impact classes, entry-point partition maps, function card tags (`SRC_*`/`SINK_*`/`BOUNDS_*`), hardening recon checklist |
| `vuln-provenance` | Evidence ladder (P1 tool-proven / P2 derived / P3 model-asserted), verification ladder (L1–L4), kill mandates, empirical gate |
| `poc-recipes` | PoC ladder (P0–P3), per-class trigger recipes, memory-corruption weaponization patterns for RCE grading |

## How the pipeline enforces quality

- **High-severity gate** — low-impact bugs (null-deref, assertion aborts, pure DoS) are demoted to a one-line "noted, not pursued" list. The report leads with what is exploitable.
- **Adversarial verification** — verifiers work under a kill mandate with cold-start review (re-derive before reading the analyst's narrative). A single empirical test outranks unanimous reviewer consensus.
- **Provenance discipline** — every claim is P1 (tool output), P2 (derivation shown), or P3 (model assertion). P3 claims are demoted to unverified, never presented as findings. CONFIRMED (dynamic, PoC-backed) is the gold tier.
- **Coverage honesty** — analysts state which partitions and functions were analyzed and which skipped. Refuted findings stay in an appendix.

## Workspace layout

```
objects/     analysis targets (binaries, firmware, dumps) — analyzed in place
tmp/         intermediate artifacts only (IDB files, crash dumps, test builds)
reports/     all documents + PoC evidence packages (reports/poc/<id>/)
```

Hard rule: nothing is ever written to `/tmp`, `$TMPDIR`, macOS private temp paths, or anywhere outside the project. `tmp/` is disposable — anything whose loss would damage the evidence chain belongs in `reports/poc/<id>/` instead.

## Requirements

- [opencode](https://opencode.ai)
- IDA Pro 9.1 with `idalib-cli` on PATH (all RE operations go through it)
- python3, clang/gcc for PoC builds, jq/rg for report assembly

## Quick start

```sh
git clone https://github.com/ylca0/reverse_vul_hunting.git
cd reverse_vul_hunting
cp your-target-binary objects/
opencode
```

Then in opencode:

```
/vulnhunt objects/your-target-binary
```

Outputs land in `reports/<name>-<date>.md` with PoC packages under `reports/poc/`.

## Adding knowledge

- New vulnerability patterns → `.opencode/skill/vuln-patterns/SKILL.md` (one section per pattern: Hex-Rays signature, key questions, severity logic)
- Threat-model concepts → `binary-threat-model`
- Verification rules → `vuln-provenance`
- PoC techniques → `poc-recipes`

## License

MIT
