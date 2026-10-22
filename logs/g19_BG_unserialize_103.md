# Pre-RINIT `BG(unserialize)` cross-request primitive on 172.16.0.103

Date: 2026-10-21
Target: Debian 12.15, Apache/2.4.68 prefork/mod_php, PHP 8.4.26 self-built
(`memory_limit 8M`, `session.upload_progress.enabled=On`, `cleanup=On`,
`session.use_cookies=0`).
All work below is on `172.16.0.103`; no target-side PHP exploit file is used
for the remote parts.

## 1. What the new intel changes

The upload_progress line is not primarily a progress-bucket UAF. The real
cross-request primitive is the **pre-RINIT** session decode path:

- `session.upload_progress` multipart handling runs before
  `PHP_RINIT_FUNCTION(basic)`.
- A session decode OOM there leaves `BG(unserialize).level = 1` (and, in the
  delayed-`__unserialize` case, `BG(serialize_lock) = 1`) across requests.
- Request B's pre-RINIT decode (`php_var_unserialize_init`) still sees that
  state before RINIT clears `BG(unserialize)`.

This is consistent with the supplied analysis: "UAF caused by
`BG(unserialize)` state persisting across requests during the pre-RINIT phase".

## 2. Confirmed on 8.4.26

### 2.1 A/B upload_progress primitive

`tools/sup_poc.py a` (12MB field after the file part) + `b` (no file):

- A returns `Allowed memory size of 8388608 bytes exhausted`.
- B returns the expected warnings:
  `Session ID is too long or contains illegal characters`,
  `Failed to read session data: files (path: /tmp)`.
- On this build B does not crash; the worker survives.

### 2.2 Decode-expansion OOM leaves BG level=1

Session file with `x|a:300000:{...}` (5.1MB on disk, expands to >8MB during
decode):

```text
Fatal error: Allowed memory size ... (tried to allocate 20971520 bytes)
Warning: PHP Request Startup: Failed to decode session object. Session has been destroyed
```

After the request, gdb on the same worker:

```text
basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e78000
basic_globals.serialize_lock    = 0
struct: last=0x7ffff5e78038 first_dtor=0x7ffff5e7b000
        entries.used_slots=1, entries.next=0
```

So the top-level `php_unserialize_data` is still allocated and its inline
`entries` are intact. This is a cross-request state leak, but not yet a freed
object.

### 2.3 Freed `var_entries` via delayed `__unserialize` OOM

A session containing a large `SplFixedArray` object:

```text
x|O:13:"SplFixedArray":100000:{i:0;i:0; ... i:1024;i:1024; i:1025;R:2; ...}
```

- The first 1025 values fill the inline `entries` and force an extra
  `var_entries` allocation.
- The rest are backreferences (`R:2;`) so decoding does not push more entries.
- Decode succeeds, then `PHP_VAR_UNSERIALIZE_DESTROY` → `var_destroy`:
  1. frees the extra `var_entries` chain,
  2. calls delayed `SplFixedArray::__unserialize`,
  3. that call allocates `size * sizeof(zval)` and OOMs.

GDB on the OOM bailout:

```text
BAILOUT BG.level=1 data=0x7ffff5f9b000
#9  spl_fixedarray_init_non_empty_struct (size=100000, array=0x7ffff5f9f000)
#10 zim_SplFixedArray___unserialize
#11 zend_call_function
```

After the request:

```text
serialize_lock = 1
unserialize.level = 1
unserialize.data = 0x7ffff5f9b000
data->last = 0x7ffff5fa0000      <- freed var_entries chunk
data->entries.next = 0x7ffff5fa0000
```

This is a genuine UAF: `data->last` points to a freed 8160-byte `var_entries`
chunk. `serialize_lock` was left at 1 because the OOM bailed out of the
`serialize_lock++/--` window around the delayed call.

### 2.4 Structure sizes on this build

```text
sizeof(struct php_unserialize_data) = 8216
sizeof(var_entries)                 = 8160   (VAR_ENTRIES_MAX = 1018)
sizeof(var_dtor_entries)            = 4096
sizeof(zend_object)                 = 56     (handlers at +0x8)
```

The intel's 8216-byte object is `struct php_unserialize_data` itself; the freed
`var_entries` is 8160/8192 on this build.

## 3. Remote large-session creation

A `PHP_SESSION_UPLOAD_PROGRESS` value of N bytes becomes a session key
`upload_progress_<N bytes>`, so a large progress field makes a large session
file without any application code:

- N = 1 MiB + a 12MB field to force OOM after the session write:
  `/tmp/sess_<sid>` = 1,048,900 bytes and is a complete/valid serialization
  (verified: ends with `}}}`; key + progress array).
- N = 2 MiB / 3 MiB: no file, the request OOMs before the session write.
- Repeated growth requests alternate file-size 1,048,900 / missing: an OOM
  request that decodes an existing session triggers
  `php_session_cancel_decode` → `session_destroy`, which unlinks the file.

So upload_progress can remotely create a **valid ~1MB session whose value is
the fixed progress array**, and can leave it behind by OOM'ing after the write.

## 4. Current blocker for the full intel chain

The intel chain needs the first request's session value to be an attacker-
crafted serialized object (`SplFixedArray` / forged `var_entries` / etc.).
`session.upload_progress` can only write the fixed progress array; its key and
string fields are length-prefixed serialization, so they cannot inject an
`O:...` value into the session file. Reaching steps 3–6 therefore needs one of:

1. a target application that stores user-controlled serialized data in
   `$_SESSION` (the common real-world case), or
2. another remote file-write primitive for `/tmp/sess_<id>`, or
3. a different session serializer/INI configuration controllable by the
   attacker.

On this 8.4.26 build, the additional `serialize_lock=1` state also means the
next pre-RINIT `php_var_unserialize_init` allocates a fresh local
`php_unserialize_data` instead of reusing `BG(unserialize).data`; the intel's
"freed `data` then reused" step may depend on the 8.5.4 destroy/cleanup path
or on an application `unserialize()`/`session_decode()` call. This needs
re-checking against the 8.5.4 source/target.

## 5. Useful artifacts

- `tools/mk_splref.py` — generate the `SplFixedArray` session payload that
  produces the freed `var_entries`.
- `tools/bg_make.py` / `tools/bg_create.py` — remote large-session creation
  via a huge progress key.
- `tools/sup_poc.py` — A/B upload_progress harness.
- `logs/g18_ASLR_ZEND_103.md` — separate app-level ASLR-on Zend-only result
  (kept for reference; it does not satisfy the "no target PHP" constraint).
