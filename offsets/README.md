# Offsets

| Architecture | Installation command | libphp SHA-256 | build-id | zval_ptr_dtor | zif_system | zif_passthru | Status | Author |
|---|---|---|---|---|---|---|---|---|
| x86_64 | `docker pull php:8.4.26-apache` | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` | `a534a5c4a890b378ef6c227590627d531eafa8ce` | `0x65EB60` | `0x465370` | `0x465380` | ✅ [Details](php-8.4.26-apache-trixie-amd64.md) | - |
| aarch64 | `docker pull --platform linux/arm64 php:8.4.26-apache` | `e160c9d173be0e170add2ab461ba2995d0dd9ac0feb6faf3e763c052c998ab4b` | `b3525423bd3d026677be6de48285e46ae5a5604b` | `0x63812B` | `0x42CD70` | `0x42CD80` | ✅ PR #6 (single worker 10/10, official workers 3/3) · local aarch64 test 1/1 · [Log](../pure/evidence/arm64_stock_20261023.log) | ideacatlab |

> On aarch64, `0x63812B` is the offset of the repeated pointer in the leak window; the ELF symbol is at `0x638120` (+0xB). The libphp SHA-256 and build-id were recorded from the local arm64 image.

## Pull requests

Pull requests are welcome for offsets for new architectures, new versions, or other installation methods. Include the SHA-256 and build-id of `libphp.so`, along with evidence of a successful run.
