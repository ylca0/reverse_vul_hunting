---
name: vuln-patterns
description: Binary vulnerability pattern catalog for auditing decompiled code. Use when analyzing Hex-Rays pseudocode or disassembly for memory-safety and logic bugs — covers stack overflow, format string, integer underflow/overflow, UAF, OOB, command injection patterns with detection heuristics and IDA pseudocode signatures.
---

# Binary Vulnerability Pattern Catalog

Audit aid for decompiled pseudocode. For each pattern: signature in Hex-Rays
output, key questions, and severity logic.

## 1. Stack Buffer Overflow — CWE-121 / CWE-24

**Signatures**
- `char buf[N]; // [xsp+..] [xbp-..] BYREF` followed by an unbounded copy into it
- `strcpy(buf, src)`, `strcat`, `sprintf(buf, fmt, ...)`, `gets`, `scanf("%s")`
- Fortified: `__strcpy_chk(dst, src, bound)` — CHECK `bound`: equals real buffer
  size → protected at runtime (still flagged as fragile); bound comes from
  attacker data or `strlen(src)` → useless
- `read(fd, buf, n)` / `recv(...)` where `n` > `sizeof(buf)` or derives from
  attacker-controlled length

**Key questions**: What is the real stack slot size? Is there a guard `if
(len < N)` BEFORE the copy — and is the comparison signed vs unsigned correct?
Can `src` exceed N (bounded by what)?

## 2. Format String — CWE-134

**Signatures**
- `printf(var)`, `printf(msg)` where the argument is not a literal
- `snprintf(buf, n, var)` — fmt position is user data
- `syslog(priority, var)`, `errx(code, var)`
- Pseudocode shows a function call with ONE argument where printf-family
  expects format+args

**Key questions**: trace the format argument to its origin. Literal → safe.
User string → `%n` write / `%x` leak. High severity when output goes back to
the attacker (echo/log handlers).

## 3. Integer Underflow/Overflow → OOB — CWE-190/191/787

**Signatures**
- Length math on unsigned: `if (len < 4) ...; payload = len - 8;` — underflow
  when 4 <= len < 8
- `n + offset`, `n * size` without overflow check, especially `malloc(n * x)`
- Signedness confusion: `int i` loop vs `unsigned int len` bound
- `for (i = 0; i < len - 1; i++)` where `len == 0` → wraps to huge

**Key questions**: What is the minimal attacker-chosen value that passes ALL
checks but makes the arithmetic wrap? Walk the exact boundary. `a2 - 8` with
`a2 >= 4` check is the classic bug — the check must be `>= 8`.

## 4. Off-by-One / Off-by-Few — CWE-193

**Signatures**
- `<=` in loop bound over an N-sized buffer
- `memcpy(dst, src, len)` where dst is `len` bytes but a terminator is also
  written: `dst[len] = 0`
- `arr[i] = ...; i++` with `i == N` reachable

## 5. Use-After-Free / Double Free — CWE-416/415

**Signatures**
- `free(v)` then any later read/write/call through the same or aliased pointer
- Two `free(v)` paths converging (error path + success path both free)
- `v = realloc(v, n)` — original pointer freed on failure → UAF on error path

**Key questions**: list ALL assignments/reads between free and next use;
check error/early-return paths for double frees.

## 6. Uninitialized Memory Use — CWE-457/908

**Signatures**
- Stack var without `= ...` used in conditional/output
- `malloc(n)` (not `calloc`) followed by partial fill, then full-buffer send
  (info leak in network daemons)

## 7. Command Injection — CWE-78

**Signatures**
- `system(var)`, `popen(var, ...)`, `execl("/bin/sh", "sh", "-c", var, NULL)`
- fmt strings like `system("ping %s", host)` built with sprintf first

## 8. Path Traversal — CWE-22

**Signatures**
- `fopen(user_path, ...)` without normalization
- `..` filtering done by single `strstr` removal (bypassable with `....//`)

## 9. Null Deref / Unchecked Return — CWE-476

**Signatures**
- `v = malloc(n); v->field = x` with no null check
- `fd = open(...)` used without checking -1
- BUT: only flag when allocation size or failure is attacker-influenced or
  the deref is in attacker-reachable code path

## 10. TOCTOU / Race — CWE-367

**Signatures**
- `access()`/`stat()` then `open()` on same path
- Signal-handler writes to shared global state

## 11. Auth Bypass / 越权 — CWE-287/862/639/798

**Signatures**
- Credential compare with early exit or non-constant-time idiom:
  `for (i = 0; pwd[i] == input[i]; i++)` — byte-by-byte loop where a length
  or content shortcut exists
- `strcmp(input, MAGIC)` / `strstr(buf, "admin")` against embedded constants
  — extract the constant, it IS the password (hardcoded cred, CWE-798)
- `auth = 0; if (check(x)) auth = 1;` where a code path skips the check but
  still reaches privileged handlers (missing AUTH_GATE)
- Token/session id derived from attacker-visible data: `token = hash(user +
  time)` with coarse time, or sequential ids (IDOR in dispatch tables)
- Privileged handler registered in a dispatch table without the gate the
  other handlers have

**Key questions**: what byte sequence satisfies the comparison with zero
knowledge? Is the gate on the same line as the action or on a different path?
Can the privileged function be reached directly (dispatch table xref)?

## 12. Privilege Escalation — CWE-250/269/426/427

**Signatures**
- setuid/setgid binary: `setuid(0)` preserved after `execve`/`system` with
  attacker-influenced argv/env (`system()` inherits privileges)
- Unsafe PATH handling: `execlp("service", ...)` / `system("service ...")`
  in a privileged binary — attacker-controlled PATH wins (CWE-426)
- Unconfined dlopen / LD_PRELOAD-able paths in privileged context
- Privilege drop failure: `setuid(getuid())` result unchecked — EPERM leaves
  root intact

**Key questions**: does the binary run with elevated privileges (check
setuid bit, launchd/LaunchDaemons config, service context)? Is every exec
call using an absolute path? Is the euid dropped before or after parsing
untrusted input?

## 13. Data Breach / Info Leak — CWE-200/457/908/522

**Signatures**
- `send(fd, stack_buf, sizeof(stack_buf))` where only part was filled —
  uninitialized tail (CWE-908) leaks stack/heap contents
- `printf("%p")`, `sprintf(..., "%p", ptr)` or logging of canary/heap
  pointers in paths reachable pre-exploit — defeats ASLR for a companion bug
- Crypto material handling: hardcoded keys/IVs, ECB mode, `rand()` (not
  `RAND_bytes`) for tokens
- Error paths echoing internal state: `snprintf(err, "auth failed for %s
  (hash=%s)", user, hash)`

**Key questions**: which bytes in the response are NOT attacker-supplied
input? Can uninitialized bytes be made deterministic (groom the fill level)?
Does the leak combine with another finding to defeat ASLR (leak + overflow =
one-shot)?

## 14. False-positive traps (kill on sight)

These look like findings and are not. Verifiers kill them; analysts avoid them:

- **Fortified `_chk` with correct bound**: `__memcpy_chk(dst, src, len,
  sizeof(dst))` — the bound is real. Only flag when the bound argument is
  attacker-derived or wrong.
- **Guarded by upstream contract**: buffer is filled by a function that
  guarantees the bound (grep its body before claiming overflow).
- **Unreachable sink**: sink exists but no path from any entry point; caller
  chain dead-ends in a handler never registered. Prove reachability or drop.
- **Canary absorbs the overflow**: small overflow lands entirely in padding/
  canary and corrupts nothing controllable — downgrade, don't kill.
- **Heap grooming required but impossible**: UAF needs specific allocator
  state that the entry point cannot produce. Check what the attacker
  controls before rating exploitability.
- **Signed compare that cannot wrap**: `if (len > 0 && len <= N)` on
  unsigned len covers the underflow — walk the exact boundary before
  claiming wrap.
- **assert()-only crash**: abort on malformed input is DoS at best, not
  memory corruption.
- **String truncation misread as bounds**: `dst[15] = 0` after an
  unbounded copy does NOT make it safe (it is the bug), but `snprintf(dst,
  sizeof(dst), ...)` IS safe — read the actual copy primitive.

## Severity matrix

| Reachability | Impact | Severity |
|---|---|---|
| remote, no auth | RCE / arbitrary write / auth bypass to privileged action | critical |
| remote, no auth | crash / info leak aiding exploitation | high |
| local attacker-controlled file | RCE as invoking user | critical |
| local input, privileged context (setuid/root daemon) | RCE / privesc | critical |
| local input | crash | medium |
| auth-gated | any | rate by post-auth blast radius; never auto-critical |
| unreachable from external input | any | low / drop |

## IDA pseudocode reading tips

- `// [xsp+Nh] [xbp-Nh]` comments give exact stack slot offsets — the buffer
  size is the DIFF to the next saved register/return address, not the
  declared `char buf[N]` (compiler may pad). Verify with `disasm -a <ea> -n 40`
  around the function prologue when precision matters.
- `BYREF` marks address-taken variables — likely copy destinations.
- `__int64 a1` style params: check `function -a <ea>` to see real signature
  and callers before assuming types.
- Hex-Rays may hide canary checks as `if (v3 != __stack_chk_guard)` blocks at
  function end — presence lowers exploitation grade, not existence of overflow.
