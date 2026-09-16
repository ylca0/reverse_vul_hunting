---
name: poc-recipes
description: PoC construction ladder and per-vulnerability-class trigger recipes for binaries — safe harm-minimizing triggers, exit-code/sanitizer verdicts, and how to package a PoC as evidence; plus memory-corruption weaponization assessment patterns (crash triage, stack pivot, ROP chain shapes, PLT reuse) for RCE-grade impact grading. Use when turning a CONFIRMED finding into a runnable proof or grading exploitability.
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

## 3. Memory-corruption weaponization patterns (RCE impact grading)

Proven assessment sequence from real-world exploit development
(CVE-2022-42475 FortiGate heap overflow). Use it to grade L4 impact honestly:
if the chain below is missing a piece, say the RCE rating is conditional.

**Step 1 — Crash triage: which hijack primitive?**
At the faulting instruction, classify:
- `call QWORD PTR [rax]` / `[reg]` — function-pointer hijack; RIP = value AT
  the address in the register. The register may itself be poisoned — check
  what the deref reads.
- `jmp/call reg` — direct register control.
- `ret` — stack smash; ROP from the overflow itself.
Grab `i r` (register snapshot) at crash time — this is the single most
valuable artifact; every later decision reads from it.

**Step 2 — Find the payload pointer (register audit)**
Scan the crash-time registers for pointers into attacker-controlled data
(verify with `x/xg $reg` — expect your pattern bytes). Rank candidates:
discard ones pointing too far into the payload (risk mprotect-ing the wrong
page). Typical outcome: 2-3 usable registers, e.g. rbx/rdi/rdx.

**Step 3 — Stack pivot (single gadget preferred)**
At a `call [rax]` hijack, the next `ret` pops from the REAL stack — useless
unless pivoted. Search shape: `push <payload_reg>; ...; pop rsp; ...; ret;`
(one gadget, because after pivot the chain must already be laid out).
**Gadget viability checklist before committing**:
- every intermediate memory access (`adc byte [rbx+0x41], bl` style) must
  have a writable, mapped target — verify at crash time with `x/xg $rbx`
- side effects clobber as few chain-relevant registers as possible
- confirm the gadget bytes yourself (disasm at the exact address), never
  trust a tool listing blindly

**Step 4 — mprotect chain (DEP bypass shape)**
Goal: `mprotect(page_align(payload), 0x5000, RWX)` then jump to shellcode.
Argument setup on System V x86-64: rdi/rsi/rdx via `pop rdi/rsi/rdx; ret;`.
When a needed move gadget is missing (`mov rdi, rax; ret;`), substitute
compositions: `pop rax; ret;` + `and rax, rdi; ret;` for page alignment +
`mov rdi, rax; call rbx;` pointing at a NOP/`ret;` gadget, followed by a
ret-sled sized to where the NOP's `ret` lands. Close with
`pop rax; ret;` + `jmp rax;` into the PLT entry, then `jmp rsp;` to slide
into the shellcode.

**Step 5 — PLT reuse over raw syscalls (embedded/ appliances)**
Environments without shell/interpreters: resolve function addresses from the
target binary itself, not generic gadgets:
```sh
objdump -D -j .plt <bin> | egrep ' <(mprotect|AES_set_decrypt_key|calloc)@plt>'
```
Reusing the target's own libc/OpenSSL PLT (mprotect, crypto primitives,
calloc) makes the payload self-sufficient. Addresses shift per firmware
version — pattern for portability: patch placeholder bytes (`0x33333333…`)
in shellcode at runtime from a per-version address table.

**Step 6 — Staged delivery (large payloads)**
Multi-MB implants embedded in the overflow buffer corrupt before the trigger
fires. Reliable shape: small resident shellcode connects back → downloads an
encrypted implant → decrypts (reusing target's crypto PLT) → writes to disk →
`execve`. Keep the in-overflow portion minimal (fits ~64k) and move bulk data
to the second stage.

**Impact grading rubric (feeds L4)**

| Chain element present | Rating wording |
|---|---|
| hijack + payload ptr in register + viable pivot gadget exists | RCE: high confidence (static) |
| above + mprotect chain + no bad chars in shellcode space | RCE: strong (conditions listed per-version) |
| crash reachable but no controllable pointer / pivot | control-flow hijack: theoretical |
| overwrite of function pointer/fn table only | label primitive, not "RCE", until chain assessed |

## 4. Input construction helpers

- Use python3 one-liners to build binary inputs; save to `reports/poc/<finding-id>-input.bin` so runs are replayable:
  `python3 -c 'import sys;sys.stdout.buffer.write(b"A"*120)' > reports/poc/F-001-input.bin`
- Protocol targets: craft one request per candidate parameter; change one
  variable at a time; keep a copy of every request that changes behavior.
- Determinism: run the crash trigger 3x; record all three exit codes. Flaky →
  note conditions, downgrade confidence wording.

## 5. PoC evidence package (per finding)

```
reports/poc/F-00X/
  input.bin (or trigger.txt / request.http)
  run.sh     (exact reproduction command)
  run.log    (command, exit code, signal, sanitizer/output excerpt)
```

The report links this directory instead of narrating "we ran it and it
crashed". If no run happened, the directory does not exist and the finding is
not CONFIRMED (dynamic).
