---
name: poc-recipes
description: PoC construction ladder and per-vulnerability-class trigger recipes for binaries — safe harm-minimizing triggers, exit-code/sanitizer verdicts, and how to package a PoC as evidence. Use when turning a CONFIRMED finding into a runnable proof for verification or a report artifact.
---

# PoC Recipes

A PoC is the smallest input that makes the vulnerability's effect **observably
real** — not a working weapon. Goal: deterministic, harmless, replayable
evidence that upgrades a finding to CONFIRMED (dynamic) or kills it.

## 0. Safety rails (non-negotiable)

- Harm-minimizing triggers: crash indicators (`'A'` fills, length overflows),
  never shellcode or weaponized payloads.
- Execute only binaries you are authorized to run in this workspace. Unknown
  or malware samples: stay static, mark `dynamic: skipped-for-safety`.
- Network daemons: bind to localhost only, own port range, kill cleanly.
- Every PoC run records: input file path or command, full command line, exit
  code / signal, sanitizer output if any.

## 1. The PoC ladder (climb one rung at a time)

| Rung | Goal | Verdict when it works |
|---|---|---|
| **P0 boundary computation** | script computes the exact trigger value (offsets, sizes, minimal failing length) — no execution | validates the math; P2 provenance |
| **P1 malformed input** | feed crafted file/argv/protocol message; observe different behavior vs normal input (error path taken, changed output) | supports reachability; still static-grade |
| **P2 crash / sanitizer** | run under ASan build (recompile if source available) or observe SIGSEGV/SIGABRT/SIGTRAP with attacker-shaped input | CONFIRMED (dynamic) for memory-safety classes |
| **P3 primitive demonstration** | show the effect beyond a crash: leaked canary/pointer printed, auth-gate skipped (privileged action executed), overwritten adjacent buffer visibly corrupted, command string echoed into a shell banner | upgrades impact assessment from theoretical to demonstrated |

## 2. Per-class recipes

**Stack overflow (CWE-121)**
- P0: buffer size from stack-slot diff; overflow length = diff to saved LR + 1.
- P2: `./bin <(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*N)')` → expect SIGSEGV/SIGABRT (canary) / SIGTRAP (macOS report).
- P3: non-crash variant — if `buf` sits next to a printed variable, overwrite it and show the print changes.

**Heap overflow (CWE-122/787)**
- P0: allocation size vs copy length from pseudocode.
- P2: ASan build (`clang -g -fsanitize=address`) if source or rebuild feasible; otherwise run and expect SIGSEGV on large sizes.
- P3: heap adjacency demo — allocate pattern shows corruption of a neighboring printed object.

**UAF / double free (CWE-416/415)**
- P2: ASan build preferred (reports `heap-use-after-free` with free/alloc stacks); plain run rarely crashes deterministically.
- P0 fallback: quote the free/write ordering from pseudocode as P1 evidence.

**Integer underflow/overflow (CWE-190/191)**
- P0: enumerate the boundary — minimal attacker length that passes all checks and wraps. Write it as a table (check passes? arithmetic wraps? sink len?).
- P2: trigger with the computed minimal value; expect OOB write crash at the sink.

**Format string (CWE-134)**
- P1: `%p.%p.%p` → leaked pointers in output = info leak confirmed.
- P3: `%n` write only on binaries where it is safe and authorized; otherwise stop at the leak.

**Command injection (CWE-78)**
- P1/P3: `` `id` / $(id) / ;id`` variants in the parameter; success = `id` output appearing in the response/banner. Local, harmless, unambiguous.

**Auth bypass / hardcoded creds (CWE-798/287)**
- P3: replay the discovered credential or craft the input that satisfies the flawed comparison; success = privileged function executes (log line, feature unlock, protected data returned).

**Info leak (CWE-200/457/908)**
- P1/P3: trigger the path; capture response bytes; identify leaked artifact (pointer, canary, uninitialized heap content, credential). One leaked canary/heap pointer demonstrably defeats ASLR for the companion overflow.

**Path traversal (CWE-22)**
- P3: `../../<known-readable-file>` to a file-consuming parameter; success = content of the outside file reflected.

## 3. Input construction helpers

- Use python3 one-liners to build binary inputs; save to `reports/poc/<finding-id>-input.bin` so runs are replayable:
  `python3 -c 'import sys;sys.stdout.buffer.write(b"A"*120)' > reports/poc/F-001-input.bin`
- Protocol targets: craft one request per candidate parameter; change one
  variable at a time; keep a copy of every request that changes behavior.
- Determinism: run the crash trigger 3x; record all three exit codes. Flaky →
  note conditions, downgrade confidence wording.

## 4. PoC evidence package (per finding)

```
reports/poc/F-00X/
  input.bin (or trigger.txt / request.http)
  run.sh     (exact reproduction command)
  run.log    (command, exit code, signal, sanitizer/output excerpt)
```

The report links this directory instead of narrating "we ran it and it
crashed". If no run happened, the directory does not exist and the finding is
not CONFIRMED (dynamic).
