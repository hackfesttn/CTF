#!/usr/bin/env python3
"""parse_cpio.py — find and extract a cpio newc archive from inside a binary.

Use case: the embedded initramfs in kernel.bin starts at offset 0xb3a67c
and ends at 0x2af1cec (TRAILER!!!). To find it, we try parsing from every
'070701' marker and keep only the run that terminates cleanly at TRAILER!!!.

⚠ Common pitfall: cpio newc has c_namesize at byte offset 94 (NOT 86).
Many tutorials online have this wrong; getting it wrong makes the parser
stop after the first entry.

Header layout (110 bytes total, all ASCII hex):
   0 .. 5    "070701"      magic
   6 .. 13   c_ino
  14 .. 21   c_mode
  22 .. 29   c_uid
  30 .. 37   c_gid
  38 .. 45   c_nlink
  46 .. 53   c_mtime
  54 .. 61   c_filesize
  62 .. 69   c_devmajor
  70 .. 77   c_devminor
  78 .. 85   c_rdevmajor
  86 .. 93   c_rdevminor
  94 .. 101  c_namesize    <<<< at +94, NOT +86
 102 .. 109  c_check

Usage:
    ./parse_cpio.py <binary>            # auto-locate + list contents
    ./parse_cpio.py <binary> extract <outdir>      # also extract files
    ./parse_cpio.py <binary> save  <out.cpio>      # save the cpio blob
"""
import os, re, sys


def parse(data: bytes, start: int, max_files: int = 20000):
    """Walk a cpio newc archive starting at `start`. Returns (files, end_offset, reason)."""
    pos = start
    files = []
    while pos < len(data) - 110 and len(files) < max_files:
        if data[pos:pos+6] != b'070701':
            return files, pos, 'not_magic'
        try:
            mode     = int(data[pos+14:pos+22], 16)
            filesize = int(data[pos+54:pos+62], 16)
            namesize = int(data[pos+94:pos+102], 16)
        except ValueError:
            return files, pos, 'bad_header'
        if namesize > 1024 or filesize > 200 * 1024 * 1024:
            return files, pos, 'crazy_sizes'
        name_off = pos + 110
        try:
            name = data[name_off:name_off+namesize-1].decode()
        except UnicodeDecodeError:
            return files, pos, 'bad_name'
        # Header + name padded to 4-byte boundary
        data_off = (name_off + namesize + 3) & ~3
        files.append({
            'name': name,
            'mode': mode,
            'size': filesize,
            'data': data[data_off : data_off + filesize],
        })
        # Data also padded to 4-byte boundary
        pos = (data_off + filesize + 3) & ~3
        if name == 'TRAILER!!!':
            return files, pos, 'trailer'
    return files, pos, 'limit'


def find_archive(data: bytes):
    """Find the longest cpio archive that ends cleanly at TRAILER!!!."""
    candidates = []
    for m in re.finditer(rb'070701', data):
        files, end, reason = parse(data, m.start(), max_files=20000)
        if reason == 'trailer':
            candidates.append((m.start(), end, len(files)))
    if not candidates:
        return None
    # Return the earliest start among the ones that share the same end (= largest archive)
    end_target = max(c[1] for c in candidates)
    candidates = [c for c in candidates if c[1] == end_target]
    candidates.sort()
    return candidates[0]   # (start, end, n_files)


def extract(files, outdir):
    os.makedirs(outdir, exist_ok=True)
    for f in files:
        if f['name'] in ('', 'TRAILER!!!'):
            continue
        path = os.path.join(outdir, f['name'])
        ftype = f['mode'] & 0o170000
        if ftype == 0o040000:                       # directory
            os.makedirs(path, exist_ok=True)
        elif ftype == 0o120000:                     # symlink
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            target = f['data'].decode(errors='replace')
            try:
                if os.path.lexists(path):
                    os.unlink(path)
                os.symlink(target, path)
            except OSError:
                pass
        else:                                       # regular file (or special)
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            with open(path, 'wb') as out:
                out.write(f['data'])


def main():
    if len(sys.argv) < 2:
        sys.exit(f"Usage: {sys.argv[0]} <binary> [extract|save] [out]")
    data = open(sys.argv[1], 'rb').read()
    print(f"  scanning {sys.argv[1]} ({len(data):,} bytes) for cpio archives…")
    found = find_archive(data)
    if not found:
        sys.exit("[-] no cpio archive ending at TRAILER!!! found")
    start, end, n = found
    print(f"  archive at 0x{start:x} – 0x{end:x}  "
          f"({end-start} bytes, {n} entries)")

    if len(sys.argv) >= 4 and sys.argv[2] == 'save':
        open(sys.argv[3], 'wb').write(data[start:end])
        print(f"  → saved cpio blob to {sys.argv[3]}")
        return

    files, _, _ = parse(data, start)
    if len(sys.argv) >= 4 and sys.argv[2] == 'extract':
        extract(files, sys.argv[3])
        print(f"  → extracted to {sys.argv[3]}/")
        return

    # Default: list interesting entries
    print(f"\n  Interesting entries (init / crypt / sbin):")
    for f in files:
        n = f['name']
        if (n in ('init', 'sbin/init', 'linuxrc')
            or n.startswith('init.d/') or n.startswith('etc/init.d/')
            or 'crypt' in n.lower() or 'luks' in n.lower()):
            print(f"    mode=0o{f['mode']:>6o}  size={f['size']:>8}  {n}")


if __name__ == '__main__':
    main()
