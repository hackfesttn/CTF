#!/usr/bin/env python3
"""extract_spl.py — strip the CHSETTINGS table from MLO to get the bare SPL.

TI X-Loader MLO format with CHSETTINGS:
   0x000 .. 0x1FF   CHSETTINGS table (512 bytes — secure-boot config)
   0x200 .. 0x203   length (LE)
   0x204 .. 0x207   load address (LE)
   0x208 ..         ARM SPL binary

For our emd1.img:
   length    = 0x15984
   load addr = 0x402F0400  (BeagleBone Black SRAM)

Usage:
    ./extract_spl.py MLO [out.bin]    # default: spl_real.bin
"""
import struct, sys

def main():
    if len(sys.argv) < 2:
        sys.exit(f"Usage: {sys.argv[0]} MLO [out.bin]")
    src = open(sys.argv[1], 'rb').read()
    out = sys.argv[2] if len(sys.argv) > 2 else 'spl_real.bin'

    if len(src) < 0x210:
        sys.exit("File too small to be MLO with CHSETTINGS")

    length    = struct.unpack('<I', src[0x200:0x204])[0]
    load_addr = struct.unpack('<I', src[0x204:0x208])[0]

    # Sanity check: load address should be in AM335x SRAM (0x4020_0000–0x4030_0000)
    if not (0x40200000 <= load_addr <= 0x40400000):
        print(f"  ! warning: unusual load addr 0x{load_addr:08x} — is this an AM335x MLO?")

    spl = src[0x208:]
    open(out, 'wb').write(spl)
    print(f"  source MLO       : {len(src)} bytes")
    print(f"  declared length  : 0x{length:x}")
    print(f"  load address     : 0x{load_addr:08x}")
    print(f"  → wrote {out} ({len(spl)} bytes)")

if __name__ == '__main__':
    main()
