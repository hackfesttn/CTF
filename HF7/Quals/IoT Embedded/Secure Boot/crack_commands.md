# emd1 — passphrase brute-force cheat sheet

## Hashes / artifacts
- Shadow hash (sha512crypt) for `root`:
  ```
  $6$H4qcq/w9xvn8kOnj$nRZp8At1XVLd7tb8dG.lHSDMEx3QVBHVIYo15zv9LHJB5gimnltYMj.qEa3HgQulCXGpf.mKCqehPlvbn1ng//
  ```
- LUKS volume: `p2.img` (sliced from `emd1.img` sectors 144585-401624)
- LUKS KDF: argon2i, time=4, memory=14806 KB, single keyslot

## 1) Hashcat — fastest path (crack shadow first)

```bash
# Save just the hash (no username:)
echo '$6$H4qcq/w9xvn8kOnj$nRZp8At1XVLd7tb8dG.lHSDMEx3QVBHVIYo15zv9LHJB5gimnltYMj.qEa3HgQulCXGpf.mKCqehPlvbn1ng//' > shadow.hash

# Straight wordlist (sha512crypt = mode 1800)
hashcat -m 1800 shadow.hash rockyou.txt

# With mangling rules (much wider coverage)
hashcat -m 1800 shadow.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1800 shadow.hash rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Show result
hashcat -m 1800 shadow.hash --show
```

GPU does this at millions of H/s; CPU at ~hundreds-to-thousands H/s.

## 2) John the Ripper — alternative

```bash
echo 'root:$6$H4qcq/w9xvn8kOnj$nRZp8At1XVLd7tb8dG.lHSDMEx3QVBHVIYo15zv9LHJB5gimnltYMj.qEa3HgQulCXGpf.mKCqehPlvbn1ng//' > shadow.txt

# Wordlist + default rules
john --wordlist=rockyou.txt --rules shadow.txt

# Show result
john --show shadow.txt
```

## 3) LUKS direct brute force (Argon2i — slow, ~1/s/core)

If the shadow password doesn't unlock LUKS, attack the keyslot directly:

```bash
# Sequential
while IFS= read -r pw; do
  if echo -n "$pw" | cryptsetup luksOpen --test-passphrase --key-file=- p2.img 2>/dev/null; then
    echo "FOUND: $pw"; break
  fi
done < rockyou.txt

# Parallel across all CPU cores
cat rockyou.txt | xargs -P "$(nproc)" -I{} -d '\n' bash -c '
  echo -n "$1" | cryptsetup luksOpen --test-passphrase --key-file=- p2.img 2>/dev/null \
    && echo "FOUND: $1"
' _ {}
```

JtR has native LUKS support too (much faster than the shell loop):

```bash
# Convert LUKS header to JtR format
python3 /usr/share/john/luks2john.py p2.img > p2.luks

# Crack
john --wordlist=rockyou.txt p2.luks
john --show p2.luks
```

## 4) hashcat for LUKS2 (mode 29541)

```bash
# hashcat needs a single LUKS sector dump for LUKS2 (mode 29541)
# Extract first 16 MB (header + keyslots) — it's all hashcat needs
dd if=p2.img of=p2_header.luks bs=1M count=16

hashcat -m 29541 p2_header.luks rockyou.txt
```

## All-in-one wrapper script
```
./crack.sh rockyou.txt p2.img
```
Tries shadow first, then falls through to LUKS if needed.
