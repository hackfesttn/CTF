#!/usr/bin/env bash
#
# emd1 CTF — passphrase cracker
# ----------------------------------------------------------------------------
# Tries a wordlist against:
#   1. The /etc/shadow root hash from the initramfs   (fast, ~5k H/s CPU, GPU much faster)
#   2. The LUKS2 keyslot of partition 2               (slow, ~1 attempt/sec because of argon2i)
#
# Hits on the SHADOW hash will probably also unlock LUKS — author very likely
# reused the same secret. So crack shadow first, then verify against LUKS.
#
# Usage:
#   ./crack.sh <wordlist> [p2.img]
#
# Example:
#   ./crack.sh /usr/share/wordlists/rockyou.txt p2.img
#
# Requires: hashcat (or john), cryptsetup
# ----------------------------------------------------------------------------
set -u

WORDLIST="${1:-}"
LUKS_IMG="${2:-p2.img}"

if [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]]; then
  echo "Usage: $0 <wordlist> [luks_image=p2.img]" >&2
  exit 1
fi

SHADOW_HASH='$6$H4qcq/w9xvn8kOnj$nRZp8At1XVLd7tb8dG.lHSDMEx3QVBHVIYo15zv9LHJB5gimnltYMj.qEa3HgQulCXGpf.mKCqehPlvbn1ng//'
echo "$SHADOW_HASH" > /tmp/sha512crypt.hash

# ----------------------------------------------------------------------------
# Stage 1 — crack root shadow hash with hashcat (sha512crypt = mode 1800)
# ----------------------------------------------------------------------------
echo "=== Stage 1: hashcat sha512crypt against $WORDLIST ==="

# Plain wordlist pass
hashcat -m 1800 -a 0 /tmp/sha512crypt.hash "$WORDLIST" --status --status-timer=30

# Mangled pass — only run if straight pass missed
if ! hashcat -m 1800 --show /tmp/sha512crypt.hash 2>/dev/null | grep -q ':' ; then
  echo
  echo "=== Stage 1b: same wordlist + best64 rules ==="
  hashcat -m 1800 -a 0 /tmp/sha512crypt.hash "$WORDLIST" \
    -r /usr/share/hashcat/rules/best64.rule \
    --status --status-timer=30
fi

CRACKED=$(hashcat -m 1800 --show /tmp/sha512crypt.hash 2>/dev/null | awk -F: '{print $NF}' | head -n1)

if [[ -n "$CRACKED" ]]; then
  echo
  echo "[+] root password recovered: '$CRACKED'"
  echo "[+] testing it against LUKS volume $LUKS_IMG..."
  if echo -n "$CRACKED" | cryptsetup luksOpen --test-passphrase --key-file=- "$LUKS_IMG" 2>/dev/null; then
    echo "[+] *** LUKS UNLOCKED with: '$CRACKED' ***"
    echo
    echo "Mount the volume:"
    echo "    sudo cryptsetup luksOpen $LUKS_IMG rootfs   # type the passphrase: $CRACKED"
    echo "    sudo mount /dev/mapper/rootfs /mnt/rootfs"
    exit 0
  else
    echo "[-] LUKS rejected the shadow password — author used different passphrase."
    echo "    Falling through to direct LUKS brute force..."
  fi
fi

# ----------------------------------------------------------------------------
# Stage 2 — direct brute force against LUKS keyslot (argon2i is slow!)
# ----------------------------------------------------------------------------
echo
echo "=== Stage 2: direct LUKS brute force on $LUKS_IMG ==="
echo "(argon2i: time=4 mem=14806 — expect ~1 attempt/sec/core)"

# Parallel via xargs. Each worker reads the wordlist and tries one passphrase.
# Skip lines we already tried via shadow.
N_PARALLEL=$(nproc)
echo "Using $N_PARALLEL parallel workers..."

cat "$WORDLIST" | tr -d '\r' | xargs -P "$N_PARALLEL" -I{} -d '\n' bash -c '
  pw="$1"
  if echo -n "$pw" | cryptsetup luksOpen --test-passphrase --key-file=- '"$LUKS_IMG"' 2>/dev/null; then
    echo "*** LUKS UNLOCKED: $pw ***"
    pkill -P '"$$"' xargs 2>/dev/null
    exit 0
  fi
' _ {}

echo "Done."
