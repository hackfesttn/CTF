#!/usr/bin/env python3
"""decrypt_zimage.py — decrypt the encrypted zImage and decompress the kernel.

The U-Boot env's loadimage script tells us:
   key = 0x07 × 16
   the image is decrypted in TWO independent 16 MB AES-128-CBC chunks
   each chunk uses IV = 0  (the env's mw.b 0x80000010 cc 16 is a red herring;
   stock U-Boot 2017.09's `aes` command always uses zero IV)

After decryption, the zImage's gzipped kernel sits at offset 0x7318.
We use raw deflate (zlib -15) past the 10-byte gzip header — Python's
gzip.decompress() chokes on this image due to padding/multiple-stream weirdness.

Usage:
    ./decrypt_zimage.py zImage [zImage_dec.bin] [kernel.bin]
"""
import sys, struct, zlib
from Crypto.Cipher import AES

KEY  = bytes([0x07]) * 16
IV   = bytes(16)
HALF = 0x1000000   # 16 MB chunk size


def main():
    if len(sys.argv) < 2:
        sys.exit(f"Usage: {sys.argv[0]} zImage [zImage_dec.bin] [kernel.bin]")
    src      = sys.argv[1]
    dec_out  = sys.argv[2] if len(sys.argv) > 2 else 'zImage_dec.bin'
    kern_out = sys.argv[3] if len(sys.argv) > 3 else 'kernel.bin'

    ct = open(src, 'rb').read()
    if len(ct) != 2 * HALF:
        print(f"  ! warning: expected 32 MB input, got {len(ct)}")

    pt = b''
    for i in range(2):
        chunk_ct = ct[i*HALF : (i+1)*HALF]
        # Each chunk decrypts independently with IV=0
        chunk_pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(chunk_ct)
        pt += chunk_pt
    open(dec_out, 'wb').write(pt)

    # Verify zImage magic at +0x24
    magic = struct.unpack('<I', pt[0x24:0x28])[0]
    start = struct.unpack('<I', pt[0x28:0x2c])[0]
    end   = struct.unpack('<I', pt[0x2c:0x30])[0]
    print(f"  decrypted size  : {len(pt)}")
    print(f"  ARM nop preamble: {pt[:16].hex()}  "
          f"({'OK' if pt[:16] == bytes.fromhex('0000a0e1')*4 else 'WRONG IV?'})")
    print(f"  zImage magic    : 0x{magic:08x}  "
          f"({'OK' if magic == 0x016f2818 else 'WRONG'})")
    print(f"  payload range   : 0x{start:x} – 0x{end:x} (size {end-start} = "
          f"{(end-start)/1024/1024:.2f} MB)")
    print(f"  → wrote {dec_out}")

    # Find embedded gzip
    gz_off = pt.find(b'\x1f\x8b\x08')
    if gz_off < 0:
        sys.exit("[-] No gzip header found in decrypted zImage")
    print(f"\n  gzip header at  : 0x{gz_off:x}")

    # Skip 10-byte gzip header, raw deflate (zlib -15)
    kernel = zlib.decompressobj(-15).decompress(pt[gz_off+10:])
    open(kern_out, 'wb').write(kernel)
    print(f"  decompressed    : {len(kernel)} bytes ({len(kernel)/1024/1024:.2f} MB)")
    print(f"  → wrote {kern_out}")

    # Quick flag grep
    import re
    flags = re.findall(rb'hackfest\{[^}]+\}', kernel)
    if flags:
        print(f"\n  hackfest{{...}} found in kernel:")
        for f in flags:
            print(f"    {f.decode()}")


if __name__ == '__main__':
    main()
