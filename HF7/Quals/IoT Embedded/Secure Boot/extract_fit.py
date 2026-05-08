#!/usr/bin/env python3
"""extract_fit.py — pull the firmware payload out of u-boot.img (FIT format).

FIT image layout for u-boot.img:
    [ FDT blob describing /images/* nodes (size in FDT header) ]
    [ padding to 8-byte boundary ]
    [ payload data — each image's offset = (FDT_padded) + node's 'data-offset' ]

Each image node has:
    data-offset : byte offset into the data area
    data-size   : payload size
    type        : 'firmware', 'kernel', 'flat_dt', etc.
    load        : load address

For our u-boot.img, the firmware image's data starts at offset 0x798
(= padded(0x791, 8)) with size 0x70ee0.

Usage:
    ./extract_fit.py u-boot.img [out.bin]
"""
import struct, sys

try:
    import fdt   # pip install --break-system-packages fdt
except ImportError:
    sys.exit("Install 'fdt' first: pip install --break-system-packages fdt")


def get_first_int(prop):
    """Return the first integer value of an fdt property, or None."""
    if prop is None:
        return None
    data = prop.data
    if isinstance(data, list) and data and isinstance(data[0], int):
        return data[0]
    return None


def main():
    if len(sys.argv) < 2:
        sys.exit(f"Usage: {sys.argv[0]} u-boot.img [out.bin]")
    src = open(sys.argv[1], 'rb').read()
    out = sys.argv[2] if len(sys.argv) > 2 else 'uboot_extracted.bin'

    # Find FDT magic (0xd00dfeed) at offset 0 (newer FIT) or 64 (legacy)
    fdt_start = None
    for off in (0, 64):
        if src[off:off+4] == b'\xd0\x0d\xfe\xed':
            fdt_start = off
            break
    if fdt_start is None:
        sys.exit("No FDT magic 0xd00dfeed found at offset 0 or 64")

    fdt_size = struct.unpack('>I', src[fdt_start+4:fdt_start+8])[0]
    print(f"  FDT at 0x{fdt_start:x}, size 0x{fdt_size:x}")

    dt = fdt.parse_dtb(src[fdt_start:fdt_start+fdt_size])

    # Data area starts on 8-byte boundary after the FDT
    data_area_start = fdt_start + ((fdt_size + 7) & ~7)
    print(f"  data area starts at 0x{data_area_start:x}")

    # Find the firmware image (skip 'flat_dt' / fdt nodes — FIT often labels DTBs as
    # firmware too, so prefer 'os=u-boot' or by name 'firmware*')
    images = dt.get_node('/images')
    target = None
    for sub in images.nodes:
        os_prop   = sub.get_property('os')
        type_prop = sub.get_property('type')
        os_name   = os_prop.data[0] if os_prop else ''
        i_type    = type_prop.data[0] if type_prop else ''
        if i_type == 'firmware' and os_name == 'u-boot':
            target = sub
            break

    if target is None:
        # Fall back: first node named 'firmware*'
        for sub in images.nodes:
            if sub.name.startswith('firmware'):
                target = sub
                break

    if target is None:
        sys.exit("No U-Boot firmware image found in FIT")

    data_offset = get_first_int(target.get_property('data-offset'))
    data_size   = get_first_int(target.get_property('data-size'))
    load_addr   = get_first_int(target.get_property('load'))

    if data_offset is None or data_size is None:
        sys.exit(f"image {target.name} missing data-offset/data-size")

    abs_off = data_area_start + data_offset
    print(f"  /images/{target.name}: offset=0x{data_offset:x} (abs 0x{abs_off:x}) "
          f"size=0x{data_size:x} load=0x{(load_addr or 0):08x}")

    payload = src[abs_off:abs_off + data_size]
    open(out, 'wb').write(payload)
    print(f"  → wrote {out} ({len(payload)} bytes)")


if __name__ == '__main__':
    main()
