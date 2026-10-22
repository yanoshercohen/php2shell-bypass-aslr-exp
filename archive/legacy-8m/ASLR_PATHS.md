# ASLR Path Analysis: Zend-Only Bypass vs. Address Leak

Date: 2026-10-21
Premise: no-ASLR HTTP-only RCE is already working (`NOASLR_REPORT.md`).
Constraints: **fully remote, HTTP-only; no target-specific PHP is constructed on the target side**. The target page has only a
plain `echo` (no session calls).

This document analyzes only the two paths with ASLR enabled and does not treat the old custom-PHP leak/ROP results as a valid deliverable.

---

## 0. Executive Summary

| Path | Current assessment | Main blocker |
|---|---|---|
| Path 1: Zend-only, leakless bypass | No reliable primitive found | All controllable writes are NUL-terminated; a partial overwrite deterministically corrupts one ASLR-relevant byte; no known fixed function address |
| Path 2: HTTP-only address leak | No usable entry point found under the default configuration | The default `session.serialize_handler=php` rejects session keys containing `\|`; the old leak requires `php_serialize` plus userland `__serialize` reentrancy |

Under the conditions of “default php.ini + vanilla session page,” ASLR has not yet been bypassed.
The experiments performed, source-code evidence, and next verifiable avenues are given below.

---

## 1. Review of Existing Primitives

The key write primitive of the no-ASLR chain:

1. Request A OOMs, leaving a dangling `PS(http_session_vars)` zend_reference (R0).
2. Request B's 56B raw value buffer can overwrite R0, writing:
   - `R0+0x00` gc: refcount=1, type=IS_REFERENCE
   - `R0+0x08` val.value: an arbitrary 8-byte pointer
   - `R0+0x10` val.type: 0x307 (IS_ARRAY_EX)
   - `R0+0x18` sources: 0
3. dtor path:
   `zend_delete_global_variable` → `zval_ptr_dtor` →
   `zend_reference_destroy` → `zend_array_destroy(val.value)` →
   `zend_hash_destroy` → `pDestructor(&bucket->val)`.
4. The best location for hosting the forged HashTable is the data of a **live 192B zend_string**
   (L=167), because its gc is not overwritten by the free-list next pointer; the contents are field values,
   controllable starting at data+0.

Thus, under ASLR, what is missing is `val.value` (a heap address) and/or `pDestructor` (a libc/libphp
code address).

---

## 2. Path 1: Zend-Only ASLR Bypass Without a Leak

Goal: without using any leak, directly construct pointers/function pointers that are insensitive to ASLR.

### 2.1 Option A: Reuse the old reference's val.value = A0 (the real session HashTable)

- The old reference's `val.value` in A points to the real session HashTable A0.
  Under no-ASLR, measurement gives A0 = `0x7ffff5e03268` (`R0+0xf48`).
- If B does not overwrite R0's val.value but instead makes A0's memory into an attacker-controlled
  forged HashTable, the heap base does not need to be known.
- Feasibility check:
  - A0 is a 56B HashTable structure (sizeof(zend_array)=56, bin 6).
  - A0's `pDestructor` is originally `ZVAL_PTR_DTOR` (a libphp pointer).
  - A0 would need to be reoccupied by a **live** allocation with controllable contents and `gc.type == IS_ARRAY`.
  - However, B has two classes of allocations with controllable contents:
    1. The raw value buffer from `multipart_buffer_read_body`: it is `efree()`d as soon as the field is processed;
       after free, the allocator writes `next_free_slot` at block offset 0, overwriting gc, so `GC_DELREF` does
       not reach zero and the array dtor is not entered.
    2. A live zend_string: its gc type is IS_STRING (6), and `rc_dtor_func` calls
       `zend_string_destroy`, not `zend_array_destroy`.
  - A live real HashTable has the correct type=7, but its `pDestructor` is the real
    `ZVAL_PTR_DTOR`; we cannot change it without changing gc.
- Conclusion: reusing A0 requires a “live, controllable, type=IS_ARRAY” allocation, which is not currently available.

### 2.2 Option B: Partial pointer overwrite (preserving the high bytes of libphp)

Idea: change A0's `pDestructor` from `ZVAL_PTR_DTOR` to another function/gadget inside libphp,
overwriting only the low 2–3 bytes and preserving the high bytes of the libphp base. This requires no leak.

Two problems need to be solved:

1. **Can we write to A0+0x30 and overwrite only the low bytes?**
   - String/raw buffer writes always include a NUL:
     `zend_string_init` writes 0 at data[len]; `multipart_buffer_read_body`
     writes 0 at out[total].
   - If N bytes are written starting at `pDestructor`, byte N is necessarily 0.
   - For example, to overwrite the low 2 bytes, `b0,b1` are controllable and `b2=0`; to overwrite the low 3 bytes,
     `b0..b2` are controllable and `b3=0`.
   - In the high bytes of the target libphp address, `b3/b4/b5` all carry ASLR randomness; forcing them to 0
     holds only if the corresponding byte of the target absolute address is already 0. This depends on the base and is unreliable.
2. **Can we find a useful target within a 2–3 byte range?**
   - Measured symbols in the current libphp build (unstripped):
     ```text
     zif_system          0x43a870
     zend_call_function  0x566d20
     zend_hash_destroy   0x5cbb90
     zend_array_destroy  0x5cbdc0
     zval_ptr_dtor       0x613c50
     ```
   - `zval_ptr_dtor` is 0xacf30 (about 700KB) away from `zend_call_function` and
     0x1d93e0 (about 1.9MB) away from `zif_system`.
   - A low-2-byte partial overwrite can only jump within the same 64KB; the low-3-byte case, with the forced
     NUL at b3=0, again depends on the base byte. There is currently no usable
     gadget that falls in the same 64KB.
   - libphp imports only `popen` (`objdump -T` shows this) and does not import `system`;
     `popen@plt` also requires the libphp base, and the second argument in rsi is not controllable.
   - The earlier `zend_call_function → zif_system` lead requires a forged FCI and belongs to
     another chain that needs the libphp base.

Conclusion: partial overwrite is currently the closest direction to the “Zend-only” idea, but the NUL
terminator is a hard blocker unless an **arbitrary-length prefix write without a terminator** can be found.

### 2.3 Option C: Allocator self-written pointer (free-list next / shadow)

- A freed block has a plaintext `next_free_slot` (heap pointer) at offset 0 and an
  XOR-encoded shadow at offset size-8.
- If the forged reference's val.value is placed at the `next_free_slot` position of a freed block,
  the allocator writes a real heap pointer for us.
- However, this pointer points to the **start of another freed block**, whose offset 0 is again a next pointer,
  not a valid array gc; `GC_DELREF` does not reach zero.
- For alignment, R0+8 must become the start of a slot in some bin; when R0=0x...2320,
  R0+8=0x...2328 is divisible only by the 8B bin (page offset 0x328=808=8×101),
  and 8B blocks have no controllable contents.
- Conclusion: a heap pointer to a controllable forged HashTable cannot be obtained directly.

### 2.4 Option D: Code at a fixed address

- The main Apache program is PIE (`file /usr/sbin/apache2` = pie executable),
  and `libphp.so` and libc are both subject to ASLR.
- The only fixed executable page is vsyscall at `0xffffffffff600000`, which provides only
  gettimeofday/time/getcpu and cannot perform arbitrary syscalls/RCE.
- Neither the main program nor the modules have a directly usable fixed PLT for `system@popen@execve` (imports
  checked; the PIE base is also randomized).
- Conclusion: no fixed code address is available.

### 2.5 Path 1 Summary

With the existing primitives, a Zend-only leakless bypass requires one of the following:

- **A partial write without a NUL** (able to change the low bytes of A0->pDestructor while preserving the high bytes);
- **A live, controllable allocation of type=IS_ARRAY** (able to reoccupy A0);
- **A combination of an allocator self-written pointer and controllable contents**;
- A real libphp function pointer that can complete the attack within the same 64KB.

None of these has been confirmed yet. The most worthwhile next step is to measure the gadgets/functions within
64KB of `zval_ptr_dtor` in libphp and search for a PHP allocation path that “writes N bytes without a terminator.”

---

## 3. Path 2: HTTP-Only Address Leak

Goal: leak the heap chunk base / libphp base / libc base into the HTTP response,
then dynamically compute addresses with the no-ASLR chain.

### 3.1 Session Serializer Restrictions Under the Default Configuration (Tested)

Defaults:

```ini
session.serialize_handler = php
session.use_only_cookies = 1
```

Before writing each session key, the default `php` encoder:

```c
smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
    /* key contains '|': abandon the entire encode and return NULL */
    fail = true;
    break;
}
smart_str_appendc(&buf, PS_DELIMITER);
php_var_serialize(&buf, struc, &var_hash);
```

Measured (gdb `ps_files_write`):

```text
progress key = upload_progress_X|E:20:"AAAAAAAAAAAAAAAAAAAA";
FWRITE key=injtest0005 klen=11 vlen=0
php_session_decode len=0
```

That is, when the progress key contains `|`, the encoder returns NULL directly and the session write is empty;
the session data length read by END cleanup is 0. **Under the default configuration, arbitrary serialized
data cannot be injected via the key.**

The default decoder does not parse the data as a C string either:

```c
while (*q != PS_DELIMITER) {
    if (++q >= endptr) { retval = FAILURE; goto break_outer_loop; }
}
```

NUL cannot bypass the `|` delimiter.

### 3.2 Dependencies of the Old Leak Primitive (Not Satisfied by the Current Constraints)

Both leaks in Section 10 of `NOTES.md` depend on:

1. `session.serialize_handler = php_serialize` (non-default; set by a script via `ini_set` or by
   application configuration).
2. A userland class `C::__serialize()` freeing the `$_SESSION` array during encoding and then
   reoccupying it with `zend_reference`/`stream_bucket_new`, creating a UAF in the encoder.
3. The application calls `session_encode()` and outputs/stores the result in a readable location.

The current target page has only a plain `echo`, no userland classes, and no `session_encode()` output;
the default handler is also `php`. Therefore, these two leaks are unreachable under the present constraints.

### 3.3 Session Data Plane Controllable via HTTP Only

Under the default configuration, the only attacker-influenced data that can enter the session file is:

- the progress key (the key name, which cannot contain `|`);
- the fixed keys/values of the progress data array:
  `start_time`, `content_length`, `bytes_processed`, `done`,
  `files[0].field_name`, `files[0].name`, `files[0].tmp_name`,
  `files[0].error`, ...
- Here `field_name`/`name` are attacker strings, but they are written as **serialized values**
  (`s:<len>:"...";`), are binary-safe, and cannot become keys or enums.

The structure read by the session decoder is generated by PHP itself; there is no attacker-controlled
`E:`/`O:`/`C:`/`R:` syntax and no cross-variable injection.

### 3.4 Candidate Leak Points and Blockers

| Candidate | Result |
|---|---|
| Injecting serialized `E:` via the progress key → enum warning `%.*s` | The default `php` encoder rejects keys containing `\|`; writes 0 bytes |
| `E:` length out-of-bounds read | A `maxlen < len` check; len is limited by the input buffer length |
| Session file as a leak carrier | Requires an encoder OOB write first; the default encoder has none |
| `unserialize` built-in class handler OOB/warnings | The default configuration cannot inject `O:`/`C:`; progress data contains only arrays/strings |
| Error message `%p`/pointer format | The session/unserialize paths have no `%p`; only the enum `%.*s` |
| `session_start` warning printing id/path (this candidate exists only when the application calls it) | Contains no memory address; id characters are restricted |
| `/proc/self/maps` | Requires target-side PHP to read a file, violating the constraints |

### 3.5 If Modifying php.ini Is Allowed (Not Application PHP)

After changing `session.serialize_handler` to `php_serialize`:

- The `|` in the progress key is no longer rejected by the encoder (`php_serialize` uses
  `php_var_serialize` to serialize the entire array and does not check keys for `|`);
- Keys can be used to inject additional session variables, triggering decode warnings/built-in class handlers;
- However, the two old leaks still require the reentrancy of “freeing the session array during encode,” and
  a vanilla page does not provide this reentrancy.

Therefore, even changing the INI does not automatically provide a leak; a purely PHP built-in
reentrancy gadget is still needed, and none has been found yet.

---

## 4. Next Experiments for Both Paths

### Path 1 (Zend-Only)

1. **Measure the libphp layout**: use `nm -D`/`objdump` to obtain the offsets of
   `zval_ptr_dtor`, `zend_call_function`, `zif_system`, and `system@plt`,
   and confirm whether a usable partial target exists within the same 64KB/16MB.
2. **Find a terminator-free write**: check whether paths such as `erealloc` growth, stream buckets, and `smart_str`
   have an allocation that “copies only a prefix and does not write a NUL”; if so, a true low-byte partial overwrite of
   A0->pDestructor becomes possible.
3. **Live reoccupation of A0**: in B, try to reoccupy A0 (a 56B HashTable) with a **live**
   controllable allocation while keeping `gc.type=IS_ARRAY`; for example:
   - use session decode to create a real small array that lands at A0;
   - then use a write that overwrites only the low bytes of pDestructor and not gc.
4. **Allocator pointer alignment**: sweep A's parameters (progress key length, SID length,
   number and size of files) to see whether R0 can be moved so that R0+8 becomes a slot in a larger bin,
   thereby using the free-list next pointer to obtain a heap pointer with a “controllable target.”

### Path 2 (Leak)

1. **Under the default configuration only**, enumerate all paths that can output attacker strings
   in warnings (`%s`/`%.*s` in `php_error`) and confirm whether any `%.*s` lacks a length check.
2. **Fuzz built-in `Serializable` class handlers**: the `unserialize()` C implementations of `ArrayObject`,
   `SplObjectStorage`, `DateTime`, `SimpleXMLElement`, `ZipArchive`,
   `Phar`, etc., looking for out-of-bounds reads/paths that print input in warnings.
   Note that the default configuration currently cannot inject `C:`/`O:` into the session, so this approach
   is meaningful only with `php_serialize` or application-controllable session data.
3. **Progress data values**: confirm whether `field_name`/`name`/`tmp_name` are
   printed by `%.*s` on any error path; none has been found in the source so far.
4. **BG(unserialize) write primitive**: if the `serialize_lock` dependency can be bypassed over HTTP only,
   the arbitrary write in `var_push` could forge a `zend_string.len` and then trigger a
   `%.*s` warning leak. This chain is currently paused because it requires application-layer
   `__wakeup`/autoload.

---

## 5. Assessment Under the Constraints

- **Zend-only, leakless**: theoretically the most elegant, but limited by the “NUL terminator + no fixed code address”
  constraint; there is currently no reliable construction.
- **Address leak**: under the default `php` serializer, progress-key injection is rejected directly by
  the encoder's `memchr('|')`; the old leak also depends on a non-default serializer plus
  userland reentrancy. No leak entry point has yet been found that is HTTP-only and requires no application code.
- If a **non-default php.ini** is allowed (`session.serialize_handler=php_serialize`),
  key injection plus built-in class handlers can be investigated further; this still is not “writing target-specific PHP,” but it
  has already departed from the default configuration.
- If the target application is allowed to have a session object/progress endpoint (an application gadget), the old
  `php_serialize` leak chain can be reused; this is an application-layer dependency and does not meet the current
  “vanilla session page” constraint.

Under the strict constraints, the current deliverable should be explicitly labeled **no-ASLR RCE**; neither ASLR path
is complete, and one of the above experiments must achieve a breakthrough.

---

## 6. Addendum: Measurements of Fixed Zend Offsets (2026-10-21)

After the user noted that “some Zend addresses may be fixed,” the following measurements were performed.

### 6.1 Fixed Offsets

With ASLR enabled (`randomize_va_space=2`), the A/B trigger was used to read the following at
`php_session_track_init`:

- The old reference R0 = **chunk + 0x2320**, consistently across three master restarts.
- Session HashTable A0 (R0->val.value):
  - A's PHPSESSID length 8..32: A0 = **chunk + 0x3268**
  - A's PHPSESSID length 1..5: A0 = **chunk + 0x3230**
- The Zend main chunk base is 2MB-aligned.
- Under the same Apache master, after killing the worker with kill -9 5 times in a row, the fresh worker's chunk
  base was completely unchanged (example: `0x7fa32de00000`, B=7). That is:
  - **The chunk base is fixed for the lifetime of a master**;
  - but it is re-randomized only when the master restarts, so a worker crash cannot retry B.

### 6.2 The Chunk Header Is Not a Code Trampoline

Dump of chunk+0x000..0x100:

- `heap`/`next`/`prev`/`free_slot[]` are all heap pointers;
- `size`/`peak`/`chunks_count`/`pid` are small integers;
- there are no libphp/libc code pointers.
- A 1-byte partial write can only make the old val.value point to `chunk+0x00XX`,
  which lands exactly in the header and has no usable pDestructor; a 2-byte partial write
  zeroes b2 (the low 3 bits of the 2MB index within a 16MB block), and measurement shows that slot is the library's read-only
  `.eh_frame` data, not a controllable Zend chunk.

### 6.3 Old Contents of A0

The old HashTable at A0=chunk+0x3268:

```text
A0+0x00 gc        = 0xffffffff00000106   (refcount is not 1)
A0+0x10 arData    = chunk+0x33c0
A0+0x30 pDestructor = libphp zval_ptr_dtor (real code pointer)
```

Because the refcount is not 1, when val.value is not overwritten, the dtor only decrements the reference
and does not enter `zend_array_destroy`; therefore, a reference had to be forged previously.

### 6.4 New Primitive: Writing A0's gc with a Binary PHPSESSID

- `php_session_valid_key()` scans as a C string; the PHPSESSID value can be
  `validprefix\0<binary>`, and the binary after the NUL still enters the
  zend_string of `progress->sid` / `PS(id)`.
- `PS(id)` is created directly with `zend_string_init`; its raw value buffer is freed first, and
  the 320B PS(id) then reuses that slot.
- Measurement: with SID length 280, `sidvalid\0...`, and a forged gc placed at SID offset 0x110,
  at B's track_init **A0's first qword becomes `0x0000000700000001`**, with no need to know the chunk base at all.
- This 320B live string is located at page3 slot 0x3140 (data 0x3158),
  and A0=0x3268 is exactly data+0x110.
- This means that **gc (refcount=1, type=IS_ARRAY) can be written relative to A0**.

### 6.5 Still Unresolved: pDestructor / arData

- When A0=0x3268, pDestructor is at A0+0x30=0x3298, which has already crossed into the **next
  320B slot** (0x3280); measurement shows that B's 320B allocation overwrites this location with
  `0xffff...`, losing the old real `zval_ptr_dtor`.
- If A's SID length is changed to 1..5, A0=0x3230 and pDestructor falls within the same
  320B slot; however:
  - To overwrite/control gc/flags/arData, the 320B string length must be ≥257, while
    pDestructor is at data offset 0x108=264, so the string copy **completely overwrites**
    pDestructor (the high bytes cannot be preserved);
  - To preserve pDestructor, the length must be ≤263, but then arData (data offset
    0xd8+0x10=232) has already been overwritten and an absolute pointer must be written, while the base is unknown;
  - To overwrite only gc/flags without touching arData, L<232 is required, but the 320B bin requires
    L≥257; the bin size is coupled to the copy length, so this cannot be done.
- The 8B header-key approach also fails: R0+8=0x2328 is aligned only to 8B slot 101 within page2,
  while page2 is occupied by startup-time 56B allocations (MAP2=bin6), not bin0;
  moreover, the free-list shadow of an 8B block already covers all 8 bytes, so the old high bytes cannot be preserved.

### 6.6 Conclusion

The fixed Zend offsets are real and usable:

- the offsets of R0, A0, and the forged HT relative to the chunk are fixed;
- the chunk base is fixed within the same master;
- the old real `zval_ptr_dtor` pointer is located at A0+0x30.

However, these alone still cannot bypass ASLR because:

1. a partial write that **does not write a NUL and changes only a prefix** is needed to preserve
   pDestructor's high bytes;
2. or arData must be made to point to a forged bucket whose **absolute address is controllable**;
3. all currently available writes are “copy the entire segment + NUL terminator,” and the bin geometry is fixed,
   so neither of the above has been constructed.

The most worthwhile next steps are:
- use A's parameters to move A0 to an address where “the string data ends at pDestructor+1”
  and the bin/slot geometry hold simultaneously (currently neither 0x3230 nor 0x3268 satisfies this);
- or find any Zend allocation/copy path that “writes only N bytes without a terminator”;
- or first leak the chunk base (fixed within the same master, so one leak can be reused).

---

## 7. Addendum: A0 Shapes and page3 bin Measurements

### 7.1 A0 Has More Than Two Values

Detailed sweep of A's PHPSESSID length (no-ASLR, page3 with a fixed 320B bin):

| A SID length | A0 (chunk offset) | gc at A0+0 | A0+0x30 |
|---|---|---|---|
| 1–13 | `0x3230` | `0x80000000005978e8` (not an array HashTable) | `0x7ffff5e61208` |
| 14–21 | `0x3268` | `0xffffffff00000106` (huge refcount) | real `zval_ptr_dtor` |
| 22–23, 32–40 | `0x3230` | same as above | not pDestructor |
| **24–30** | **`0x3310`** | **`0xc000040700000001`** (rc=1, type=IS_ARRAY) | **real `zval_ptr_dtor`** |

`0x3310` is the first A0 that “can itself be used as a HashTable”:

```text
A0=chunk+0x3310
A0+0x00 = 0xc000040700000001   gc: rc=1, type=IS_ARRAY
A0+0x10 = chunk+0x4900/0x4540  arData (real heap pointer)
A0+0x30 = libphp zval_ptr_dtor (real code pointer)
```

That is, **gc/flags do not need to be forged**; with the stale reference's val.value=A0,
`zend_array_destroy(A0)` follows the real array path.

### 7.2 The page3 Bin Is Fixed

Under ASLR/no-ASLR, B's chunk page map is always:

```text
page1 bin3 (32B)
page2 bin6 (56B)
page3-7 bin16 (320B)
page8-12 bin20 (640B)
```

Testing with the custom request header `X-Pad: A*N` (N=0/96/320/480/700/1000) leaves the page map completely unchanged.
gdb catches the first 320B allocation at `zend_mm_alloc_small_slow`:

```text
zend_mm_alloc_small_slow(bin_num=16)
  zend_hash_real_init_mixed_ex
  zend_hash_real_init_mixed
  _zend_hash_add_or_update_i
  zend_hash_add
```

The first 640B allocation is `zend_hash_do_resize` for the same HashTable. Therefore, the 320B bin on page3
is a fixed startup-time allocation for HashTable arData and **cannot be changed via request headers/fields**.

### 7.3 320B Slot Geometry and A0=0x3310

A0=0x3310 is in page3's 320B slot2 (block `0x3280`, data `0x3298`):

```text
A0 = 0x3310 = slot2 data + 0x78
arData       = A0+0x10 = slot2 data + 0x88
nNumUsed     = A0+0x18 = slot2 data + 0x90
pDestructor  = A0+0x30 = slot2 data + 0xa8
```

- A 320B zend_string in slot2 has data starting at 0x3298, and its length can only be 232..295.
- To overwrite/control pDestructor (data offset 0xa8=168), a copy of length ≥168 is required;
  but the minimum length for the 320B bin is 232, so the copy **necessarily also overwrites arData**
  (offset 0x88=136) and the preceding gc/flags.
- To NUL only byte 0 of pDestructor (preserving the high bytes), L=168 is required; this corresponds to
  alloc=193 → **224B bin**, which cannot occupy 320B slot2.
- To preserve arData (not overwrite it), L<136 is required, making it even less possible to occupy a 320B slot.
- Therefore, although A0=0x3310 has a valid gc, it is still constrained by “copy length vs bin size”:
  pDestructor cannot be partially overwritten while arData is preserved.

### 7.4 Current Assessment

- Fixed Zend offsets do exist, and A0=0x3310 provides a real, controllable starting point with rc=1;
- but the 320B bin on page3 is fixed, and the data length window of a 320B slot (232..295)
  does not match A0's internal field offsets (arData 136, pDestructor 168);
- a write primitive that “writes only a prefix without a NUL” is still missing, as is a relative pointer that can make
  arData point to controlled data.

This approach has not yet produced an end-to-end result; no-ASLR RCE remains the only verified code execution.
