---
name: binary-threat-model
description: Threat modeling for compiled binaries — crown-jewel impact classes (RCE, auth bypass, info leak, privilege escalation), entry-point partitioning for parallel agents, and function card tag vocabulary (SRC_*/SINK_*/BOUNDS_*) for source-to-sink chain discovery. Use before deep binary analysis to decide where to hunt and what severity a finding carries.
---

# Binary Threat Modeling

A threat model answers "what could go wrong, via which entry, with what
impact" **independently of any specific bug**. A threat ("attacker achieves
memory corruption via untrusted firmware update parsing") survives a patch; a
vulnerability ("line 0x4012AC does not bounds-check `len`") does not. The
triage agent writes the threat model; analysts hunt inside it; verifiers and
PoC forgers score against it.

## 1. Crown-jewel impact classes (hunt priority order)

Only these outcomes justify a critical/high finding. Every analysis decision
optimizes for reaching one of them.

| Class | What it looks like in a binary | Typical CWEs |
|---|---|---|
| **RCE / control-flow hijack** | attacker-controlled write into stack/heap, command injection, format-string `%n` write, vtable/fnptr overwrite | CWE-121, 787, 78, 134, 416 |
| **Auth bypass / 越权** | password compare with early-exit loop, hardcoded credential, token derived from attacker data, missing auth check on privileged handler, IDOR in request dispatch | CWE-798, 347, 287, 862, 639 |
| **Privilege escalation** | setuid binary with unsafe path/env handling, privilege drop failure, service running as root parsing untrusted input, `execve`/`system` with attacker-influenced args | CWE-78, 426, 427, 250, 269 |
| **Data breach / info leak** | uninitialized memory sent to socket, pointer/stack canary printed, heap contents echoed in error path, crypto key logged, secret hardcoded | CWE-457, 908, 200, 798, 327 |

Everything else (DoS, null-deref at fixed offset, assertion abort, leak of
public data) is a **side dish**: note it, never let it consume the budget.

## 2. Entry points & trust boundaries (partition map)

Enumerate every place external bits enter, then partition work across agents
by entry point — one agent per partition keeps each context small and clean.

| entry point | trust boundary | attacker control | typical reachable assets |
|---|---|---|---|
| network socket / HTTP endpoint | remote, unauthenticated | full bytes, headers, lengths | all crown jewels |
| file opened from user flow | local, attacker-authored file | full bytes | RCE as invoking user |
| argv / env of privileged binary | local, pre-auth for setuid | strings + lengths | privilege escalation |
| IPC / D-Bus / named pipe | local, cross-privilege | message bytes | elevation to service uid |
| config/database/registry values | semi-trusted, tamperable | attacker-influenced | depends on consumer privilege |
| firmware / update package | supply chain, signed? | crafted package if signature broken | persistent implant |

For each entry point record: function address, input buffer origin, length
control, and which sinks are reachable within ~6 call hops. That last column
is the partition map for parallel analysts.

## 3. Function card tag vocabulary

While reading, tag every relevant function with a card of cheap labels. Cards
turn multi-hop chain discovery into set intersection — find `SRC_*` functions
and `SINK_*` functions, then walk call edges between them.

**Sources**
- `SRC_NET` — recv/read/socket message parsing
- `SRC_FILE` — fopen/fread/mmap of attacker-supplied files
- `SRC_ARGV` / `SRC_ENV` — argv, getenv
- `SRC_IPC` — D-Bus, pipe, shared memory
- `SRC_LEN` — any length/size field read from external bytes

**Sinks**
- `SINK_MEMWRITE` — memcpy, strcpy, sprintf, `[xsp+N]` stores with attacker length
- `SINK_ALLOC` — malloc/calloc/realloc with computed sizes (integer overflow candidates)
- `SINK_EXEC` — system, popen, execl/execve, dlopen
- `SINK_FMT` — printf/syslog/errx with non-literal format
- `SINK_AUTH` — setuid/setgid, auth handlers, privilege transitions
- `SINK_NETOUT` — send/write to socket (where a leak would surface)
- `SINK_FREE` — free sites feeding UAF analysis

**Bounds / hygiene**
- `BOUNDS_NONE` — no check guarding the sink
- `BOUNDS_SIGNEDNESS` — check exists but signed/unsigned mismatch suspected
- `BOUNDS_FORTIFY` — `__*_chk` variants; the bound argument must be audited
- `AUTH_GATE` / `AUTH_MISSING` — privileged handlers with/without a check

**Chain heuristic**: a finding is only critical/high when a path
`SRC_* → (LEN math) → SINK_*` exists with no `BOUNDS_*`/`AUTH_GATE` guarding
the sink. When direct edges are absent, list near-miss chains as explicit
candidate paths for the analyst to audit — do not invent them.

## 4. Open questions (record, don't guess)

Threat models from static analysis alone always leave gaps. Write them down
so the report can carry them honestly:
- who actually supplies the input in production (remote client? local user?
  wrapper service?)
- build hardening of the shipped binary (canary, PIE, FORTIFY, RELRO, ASLR) —
  changes exploitability, not severity class
- allocator (glibc/musl/custom) — changes heap-exploitation primitives
- is there an auth gate in front, and can it be reached without credentials

## 5. Outputs

`reports/threat-model-<binary-name>.md` with: system context, crown-jewel
candidates for THIS binary, the entry-point table (the partition map), initial
card tags for high-priority functions, and open questions. Downstream agents
must consume this instead of re-deriving it.
