# php:8.4.26-apache / Debian 13 (trixie) / x86_64

Recorded: 2026-10-23
Status: end-to-end verification passed (`uid=33(www-data)`)

## Build identity

| Field | Value |
|---|---|
| Image | `php:8.4.26-apache` |
| Image digest (when recorded) | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| image ID | `46b195b6378e` |
| Distribution | Debian GNU/Linux 13 (trixie) |
| Architecture | x86_64 |
| PHP | 8.4.26 (NTS, mod_php), build Oct 21 2026 00:31:19 |
| Apache | 2.4.69 (Debian) |
| libphp.so | `/usr/lib/apache2/modules/libphp.so` |
| libphp SHA-256 | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` |
| libphp GNU build-id | `a534a5c4a890b378ef6c227590627d531eafa8ce` |

When matching a build, prioritize the SHA-256 and build-id of `libphp.so`;
the image referenced by a tag can change when it is rebuilt in the registry.

## libphp symbol offsets

Relative to the libphp load base:

| Symbol | Offset | Binding |
|---|---|---|
| `zval_ptr_dtor` | `0x65EB60` | GLOBAL |
| `zif_system` | `0x465370` | LOCAL |
| `zif_passthru` | `0x465380` | LOCAL |

Runtime address = `libphp_base + offset`. The chain derives
`libphp_base = value - 0x65EB60` from the repeated `zval_ptr_dtor` pointer
in the out-of-bounds read window.

## Heap / structure offsets

For the chain using the current official 128M configuration and the `files`
session handler, either with the single-worker baseline or with requests
pinned to the same child under the official worker configuration:

| Name | Expression | Description |
|---|---|---|
| fake zend_array `S` | `main_chunk + 0xF8398` | stage-3 forged HashTable |
| `hsv` after A2 | `main_chunk + 0x7D720` | `PS(hash_serialize_verifier)` points to the heap |
| `PS(id)` | `ps_globals + 0x10` | |
| `PS(mod_data)` | `ps_globals + 0x60` | 40B `ps_files` |
| `PS(send_cookie)` | `ps_globals + 0x15E` | 1 byte |
| `PS(hash_serialize_verifier)` | `ps_globals + 0x168` | |
| main chunk fingerprint | 87 pointers in a 2MiB cluster | select the cluster with a count of 87 in the leak window |
| id chunk / libphp clusters | 7495 / 1095 pointers | 0xC8000 (800KB) window |

These heap offsets are tied to the current PHP build and 128M configuration;
changing the version or configuration requires recalibration.

## Target configuration

- Official `php.ini-production`: `display_errors=Off`, `memory_limit=128M`,
  `post_max_size=8M`, `max_input_vars=1000`
- Official prefork: `StartServers 5`, `MaxRequestWorkers 150`
- Use `--workers 150` (occupies 149 children and pins A1/B1/A2/B2 to the same
  child); use `--workers 1` for the single-worker baseline

## Verification

- Official worker mode: 10/10
- Single-worker baseline: 20/20
- Fresh clone followed by the README instructions: 2/2
- Proof: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

Reproduction:

```bash
./pure/run_pure.sh
python3 exploit.py --port 18110
```

Logs:

- `pure/evidence/official_workers_20261022.log`
- `pure/evidence/pwn_pure_batch_20261022.log`
- `pure/evidence/clone_readme_20261023.log`

## Notes

- These offsets apply only to the `libphp.so` identified above (SHA-256/build-id).
  A different PHP patch version, distribution, image build, or CPU architecture
  (such as arm64) requires a new record.
- `zif_system` / `zif_passthru` are LOCAL symbols; use `nm --defined-only`
  or `readelf -sW`, rather than relying only on `nm -D`.
- Incorrect offsets can crash the worker immediately; verify only in authorized environments.
