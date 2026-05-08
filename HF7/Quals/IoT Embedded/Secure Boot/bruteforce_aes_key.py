#!/usr/bin/env python3
"""bruteforce_aes_key.py — slide a 16-byte window over candidate binaries
trying each as an AES-128-CBC key (zero IV) for the U-Boot env.

CONFIG_ENV_AES uses a hardcoded 16-byte key returned by the board's
override of env_aes_cbc_get_key(). Since the SPL and U-Boot binaries
are <600KB combined, exhaustively trying every 16-byte aligned window
is trivial — we score the trial decryption by counting printable ASCII
and checking for the '=' character (env entries are key=value).

Usage:
    ./bruteforce_aes_key.py uboot.env spl_real.bin uboot_extracted.bin

A valid env decryption produces text like:
    arch=arm\\x00args_mmc=run finduuid;...
"""
import sys
from Crypto.Cipher import AES   # pip install --break-system-packages pycryptodome


def looks_like_env(pt: bytes) -> int:
    """Higher = more env-like. Returns 0 if no '=' in first 32 bytes."""
    if b'=' not in pt[:32]:
        return 0
    return sum(1 for x in pt if 32 <= x < 127 or x == 0)


def main():
    if len(sys.argv) < 3:
        sys.exit(f"Usage: {sys.argv[0]} <uboot.env> <bin1> [bin2 …]")
    env = open(sys.argv[1], 'rb').read()
    if len(env) < 4 + 64:
        sys.exit("uboot.env is too short")
    # First 4 bytes are CRC32, remainder is AES-CBC ciphertext
    ct = env[4:4+64]   # 4 blocks is plenty to score on

    best = []
    for path in sys.argv[2:]:
        bin_data = open(path, 'rb').read()
        for off in range(len(bin_data) - 16):
            key = bin_data[off:off+16]
            try:
                pt = AES.new(key, AES.MODE_CBC, b'\x00'*16).decrypt(ct)
            except ValueError:
                continue
            score = looks_like_env(pt)
            if score >= 50:
                best.append((score, path, off, key, pt))

    best.sort(reverse=True)
    if not best:
        print("[-] No candidate key found.")
        sys.exit(1)

    print("Top candidates:")
    for score, path, off, key, pt in best[:10]:
        print(f"  score={score}  {path} @ 0x{off:x}")
        print(f"    key (hex): {key.hex()}")
        printable = bytes(b if 32 <= b < 127 or b in (9,10,13) else 0x2e for b in pt)
        print(f"    plaintext: {printable.decode('latin1')!r}")

    # Print the best as the canonical answer
    score, path, off, key, _ = best[0]
    print(f"\n[+] Likely AES-128 env key:")
    print(f"    {key.hex()}")
    print(f"    found in {path} at offset 0x{off:x}")


if __name__ == '__main__':
    main()
