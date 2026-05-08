#!/usr/bin/env python3
"""decrypt_env.py — decrypt CONFIG_ENV_AES-encrypted U-Boot env file.

Format:
    [4 bytes little-endian CRC32 of body][AES-128-CBC encrypted body, IV=0]

Body, once decrypted:
    key1=value1\\0key2=value2\\0...keyN=valueN\\0\\0  (double-NUL terminates)

Usage:
    ./decrypt_env.py uboot.env <hex_key_32_chars> [out.bin]
"""
import sys, struct, zlib
from Crypto.Cipher import AES


def main():
    if len(sys.argv) < 3:
        sys.exit(f"Usage: {sys.argv[0]} uboot.env <16-byte hex key> [out.bin]")
    env = open(sys.argv[1], 'rb').read()
    key = bytes.fromhex(sys.argv[2])
    if len(key) != 16:
        sys.exit("Key must be 16 bytes (32 hex chars)")
    out = sys.argv[3] if len(sys.argv) > 3 else 'uboot_env_decrypted.bin'

    crc_stored = struct.unpack('<I', env[:4])[0]
    crc_calc   = zlib.crc32(env[4:]) & 0xFFFFFFFF
    print(f"  stored CRC: 0x{crc_stored:08x}")
    print(f"  calc'd CRC: 0x{crc_calc:08x}  ({'MATCH' if crc_stored == crc_calc else 'MISMATCH'})")

    pt = AES.new(key, AES.MODE_CBC, b'\x00'*16).decrypt(env[4:])
    open(out, 'wb').write(pt)
    print(f"  → wrote {out} ({len(pt)} bytes)")

    # Parse env entries
    entries, buf = [], bytearray()
    for b in pt:
        if b == 0:
            if buf:
                entries.append(bytes(buf))
                buf = bytearray()
            else:
                break   # double-NUL = end of env
        else:
            buf.append(b)
    print(f"\n  Parsed {len(entries)} env entries")
    # Print interesting ones
    for e in entries:
        s = e.decode(errors='replace')
        k = s.split('=', 1)[0]
        if any(t in k.lower() for t in ('flag', 'fl4g', 'load', 'aes', 'crypt', 'luks')):
            print(f"    {s}")


if __name__ == '__main__':
    main()
