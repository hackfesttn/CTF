#!/usr/bin/env python3
"""parse_mbr.py — dump MBR partition layout and FAT16 directory of emd1.img.

Usage:
    ./parse_mbr.py emd1.img
"""
import struct, sys

def parse_mbr(img: bytes):
    print(f"Image size: {len(img):,} bytes ({len(img)/1024/1024:.1f} MB)")
    print("\n=== MBR partitions ===")
    for i in range(4):
        e = img[446 + i*16 : 446 + (i+1)*16]
        ptype = e[4]
        if ptype == 0:
            continue
        start_lba = struct.unpack('<I', e[ 8:12])[0]
        n_sectors = struct.unpack('<I', e[12:16])[0]
        print(f"  #{i}: type=0x{ptype:02x}  "
              f"start=sector {start_lba} (byte 0x{start_lba*512:x})  "
              f"count={n_sectors}  size={n_sectors*512/1024/1024:.1f} MB")

    # Calculate gaps
    parts = []
    for i in range(4):
        e = img[446 + i*16 : 446 + (i+1)*16]
        if e[4]:
            parts.append((struct.unpack('<I', e[8:12])[0],
                         struct.unpack('<I', e[12:16])[0]))
    parts.sort()
    end_prev = 1
    for start, count in parts:
        if start > end_prev:
            gap = start - end_prev
            print(f"  GAP sectors {end_prev}-{start-1} ({gap} sectors, "
                  f"{gap*512/1024/1024:.2f} MB)")
        end_prev = start + count

def parse_fat16_root(img: bytes, part_start_byte: int):
    """Parse a FAT16 partition's root directory, including LFN reconstruction."""
    fat = img[part_start_byte:]
    bps  = struct.unpack('<H', fat[11:13])[0]
    spc  = fat[13]
    rsvd = struct.unpack('<H', fat[14:16])[0]
    nfats = fat[16]
    nroot = struct.unpack('<H', fat[17:19])[0]
    spf  = struct.unpack('<H', fat[22:24])[0]
    root_off = (rsvd + nfats * spf) * bps
    print(f"\n=== FAT16 (OEM={fat[3:11]!r}) ===")
    print(f"  bytes/sector={bps} sec/cluster={spc} reserved={rsvd} "
          f"nFATs={nfats} root_entries={nroot} sec/FAT={spf}")
    print(f"  root dir at +0x{root_off:x}, data area at "
          f"+0x{root_off + nroot*32:x}")
    print(f"\n  {'state':<8} {'name':<48} {'size':>10}  cluster  attr")
    print(f"  {'-'*8} {'-'*48} {'-'*10}  {'-'*7}  ----")

    lfn_buf = []
    for i in range(nroot):
        e = fat[root_off + i*32 : root_off + (i+1)*32]
        if e[0] == 0:
            break
        attr = e[11]
        deleted = e[0] == 0xE5
        if attr == 0x0F:                    # LFN entry
            chars = bytes(e[1:11] + e[14:26] + e[28:32])
            try:
                s = chars.decode('utf-16-le').rstrip('\xff').rstrip('\x00')
            except UnicodeDecodeError:
                s = ''
            seq = e[0] & 0x1F
            lfn_buf.append((seq, s))
            continue
        # SFN entry
        sfn  = e[:8].rstrip(b' ').decode('latin1','replace')
        ext  = e[8:11].rstrip(b' ').decode('latin1','replace')
        name = sfn + ('.' + ext if ext else '')
        cluster = struct.unpack('<H', e[26:28])[0]
        size = struct.unpack('<I', e[28:32])[0]
        full = ''
        if lfn_buf:
            lfn_buf.sort()
            full = ''.join(s for _, s in lfn_buf).split('\x00')[0]
        lfn_buf = []
        flag = '*DEL*' if deleted else '     '
        print(f"  {flag:<8} {(full or name)!r:<48} {size:>10}  "
              f"{cluster:>7}  0x{attr:02x}")

def main():
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <image.bin>")
    img = open(sys.argv[1],'rb').read()
    parse_mbr(img)
    parse_fat16_root(img, 128 * 512)        # FAT16 partition starts at sector 128

if __name__ == '__main__':
    main()
