#!/usr/bin/env bash
# runme.sh — full emd1 chain solver, end-to-end. Run from the directory that
# contains emd1.img. Produces flag1..3 and recovers the encrypted artifacts
# needed to attack flag 4 (LUKS) with rockyou.
#
# Requires: python3 with pycryptodome and fdt installed:
#     pip install --break-system-packages pycryptodome fdt

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG="${1:-emd1.img}"
[[ -f "$IMG" ]] || { echo "usage: $0 emd1.img" >&2; exit 1; }

OUT="solve_out"
mkdir -p "$OUT"

echo "===================================================="
echo "  Stage 0 — slice partitions out of $IMG"
echo "===================================================="
python3 "$HERE/parse_mbr.py" "$IMG" | tee "$OUT/00_layout.txt"

# Slice the disk image
python3 - <<PYEOF
img = open("$IMG","rb").read()
open("$OUT/p1.img","wb").write(img[128*512:131200*512])           # FAT
open("$OUT/hidden.img","wb").write(img[131200*512:144585*512])    # gap LUKS
open("$OUT/p2.img","wb").write(img[144585*512:(144585+257040)*512])  # rootfs LUKS
PYEOF

# Mount FAT (read-only) — we just need a few files
python3 - <<PYEOF
import os
os.makedirs("$OUT/p1", exist_ok=True)
try:
    from pyfatfs.PyFatFS import PyFatFS
    from fs.copy import copy_fs
    src = PyFatFS("$OUT/p1.img", read_only=True)
    copy_fs(src, "$OUT/p1")
except ImportError:
    print("(pyfatfs not installed; installing)")
    import subprocess
    subprocess.check_call(["pip","install","--break-system-packages","pyfatfs"])
    from pyfatfs.PyFatFS import PyFatFS
    from fs.copy import copy_fs
    src = PyFatFS("$OUT/p1.img", read_only=True)
    copy_fs(src, "$OUT/p1")
PYEOF
ls -la "$OUT/p1/"

echo ""
echo "===================================================="
echo "  Stage 1 — Flag 1 (uEnv.txt, plaintext)"
echo "===================================================="
echo "  fl4g line:"
grep -E "^fl4g=" "$OUT/p1/uEnv.txt" || true

echo ""
echo "===================================================="
echo "  Stage 2 — Flag 2 (decrypt uboot.env)"
echo "===================================================="
python3 "$HERE/extract_spl.py" "$OUT/p1/MLO" "$OUT/spl_real.bin"
python3 "$HERE/extract_fit.py" "$OUT/p1/u-boot.img" "$OUT/uboot_extracted.bin"
KEY=$(python3 "$HERE/bruteforce_aes_key.py" "$OUT/p1/uboot.env" \
        "$OUT/spl_real.bin" "$OUT/uboot_extracted.bin" \
        | awk '/Likely AES-128/{getline; print $1}')
echo "  → recovered AES key: $KEY"
python3 "$HERE/decrypt_env.py" "$OUT/p1/uboot.env" "$KEY" "$OUT/uboot_env.bin"
grep -ao 'fl4g=hackfest{[^}]*}' "$OUT/uboot_env.bin" || true

echo ""
echo "===================================================="
echo "  Stage 3 — Flag 3 (decrypt zImage, decompress kernel)"
echo "===================================================="
python3 "$HERE/decrypt_zimage.py" "$OUT/p1/zImage" "$OUT/zImage_dec.bin" "$OUT/kernel.bin"

echo ""
echo "===================================================="
echo "  Stage 4 — locate embedded initramfs in kernel"
echo "===================================================="
python3 "$HERE/parse_cpio.py" "$OUT/kernel.bin" save "$OUT/initramfs.cpio"
python3 "$HERE/parse_cpio.py" "$OUT/kernel.bin" extract "$OUT/initramfs"
echo ""
echo "  init.d/19-crypt content:"
echo "  ----"
cat "$OUT/initramfs/init.d/19-crypt"
echo "  ----"

echo ""
echo "===================================================="
echo "  Stage 5 — flag 4: LUKS partition"
echo "===================================================="
echo "  See $OUT/p2.img — brute force with:"
echo "    hashcat -m 29541 $OUT/p2.img rockyou.txt"
echo "  or:"
echo "    ./crack.sh rockyou.txt $OUT/p2.img"
