# Secure-Boot Chain CTF
**Author:** maro · **Tags:** reversing, forensics, cryptography, embedded · **Flags:** 4

---

## TL;DR

A 196 MB BeagleBone Black eMMC dump (`emd1.img`) containing a four-stage "secure boot" chain. Each stage encrypts the next, with the key for stage *N+1* hidden inside stage *N*'s plaintext — except the final stage, where the secret leaks out of the device entirely:

| # | Container | Cipher | Key source | Flag |
|---|---|---|---|---|
| 1 | `uEnv.txt` | none | plaintext | `hackfest{s3cur1ty_by_0bscur1ty_m0r3_lurk5_b3n3ath_th3_eye}` |
| 2 | `uboot.env` | AES-128-CBC | hardcoded in SPL & U-Boot binaries | `hackfest{env_aes_h4s_s3curity_c0nc3rns_and_1s_n0t_rec0mmend3d_f0r_use}` |
| 3 | `zImage (Linux Kernel) | AES-128-CBC ×2 chunks | inside decrypted env | `hackfest{h0w_d0_y0u_f33l_g41n1ng_r00t_acc3ss_0n_th3_dev1ce}` |
| 4 | LUKS2 partition | AES-XTS, Argon2i | typed at boot console — "in clear text" everywhere except the disk | `hackfest{pa$$phr@se_s4v3d_1n_cle4r_t3xt?!}` |

---

## 0. Initial recon — image layout

```text
$ ls -la emd1.img
-rw-r--r-- 1 root root 205,632,000 emd1.img      # 196.1 MB
```

```text
$ python3 -c "
import struct
img = open('emd1.img','rb').read(512)
for i in range(4):
    e = img[446 + i*16 : 446 + (i+1)*16]
    if e[4]:
        print(f'  type=0x{e[4]:02x} start={struct.unpack(\"<I\",e[8:12])[0]} count={struct.unpack(\"<I\",e[12:16])[0]}')
"
  type=0x0c start=128    count=131072    # FAT16-LBA, 64 MB
  type=0x83 start=144585 count=257040    # Linux, 125 MB
```

The MBR declares **two** partitions, but the math reveals an **unallocated 6.85 MB gap** between them (sectors 131200–144584):

```
[ 0..127  ]  MBR + reserved (zeroed)
[ 128.. ]    Partition 1   FAT16   64 MB    boot files
[ 131200.. ] GAP            6.85 MB  (LUKS2 magic at start — hidden volume)
[ 144585.. ] Partition 2   raw      125 MB   LUKS2 encrypted rootfs
```

Sliced into individual files (`p1.img`, `hidden.img`, `p2.img`) for the rest of the work.

The FAT partition mounts cleanly and contains the boot artifacts:

| File | Size | Purpose |
|---|---|---|
| `MLO` | 88,956 B | TI X-Loader / SPL with CHSETTINGS header |
| `u-boot.img` | 654,432 B | FIT-wrapped U-Boot 2017.09 |
| `uEnv.txt` | 915 B | Plain U-Boot env overrides |
| `uboot.env` | 131,060 B | Encrypted U-Boot env (entropy 7.9985) |
| `am335x-boneblack.dtb` | 61,895 B | Stock device tree |
| `zImage` | 33,554,432 B | Encrypted Linux kernel (entropy 8.0) |

Plus dozens of **deleted** entries — these turn out to matter much later (see §4).

---

## 1. Flag 1 — `uEnv.txt` (plaintext)

```text
$ cat /mnt/p1/uEnv.txt
#commitid=c98ac3487e413c71e5d36322ef3324b21c6f60f9
bootpart=0:2
bootfile=zImage
console=ttyO0,115200n8
fdtaddr=0x88000000
fdtfile=am335x-boneblack.dtb
loadaddr=0x82000000
mmcroot=/dev/mmcblk1p2 ro
mmcrootfstype=ext4 rootwait
optargs=consoleblank=0
nohdmi=bbb-nohdmi.dtb
fl4g=hackfest{s3cur1ty_by_0bscur1ty_m0r3_lurk5_b3n3ath_th3_eye}
mmcargs=setenv bootargs console=${console} ${optargs} root=${mmcroot} ...
uenvcmd=if run loadfdt; then echo Loaded ${fdtfile}; if run loadimage; bootz ${loadaddr} - ${fdtaddr}; fi; fi;
```

> **Flag 1:** `hackfest{s3cur1ty_by_0bscur1ty_m0r3_lurk5_b3n3ath_th3_eye}`

The variable name `fl4g` is the giveaway. The flag's text — "security by obscurity, more lurks beneath the eye" — already hints there's more, and that the rest is hidden via *obscurity* (i.e. weakness, not strength).

Also note `mmcroot=/dev/mmcblk1p2` — the kernel is being told to mount partition 2 directly as ext4. But partition 2 is LUKS-encrypted. That mismatch becomes important in §4.

---

## 2. Flag 2 — decrypting `uboot.env`

### 2.1 Recon

```text
$ python3 -c "
import math, sys
d = open('uboot.env','rb').read()
c=[0]*256
for b in d: c[b]+=1
n=len(d); H=-sum((x/n)*math.log2(x/n) for x in c if x)
print(f'size={n} entropy={H:.4f}')
print(f'first 32 bytes: {d[:32].hex()}')
"
size=131060 entropy=7.9985
first 32 bytes: 9fcad84ddca6e3df9cce9d... (random-looking)
```

The first 4 bytes are a CRC32 of the rest, then the body is encrypted. This format matches the **`CONFIG_ENV_AES`** option that existed in mainline U-Boot until early 2018 (and was then removed because of well-known cryptographic issues — foreshadowing flag 2's text).

CONFIG_ENV_AES uses **AES-128-CBC with a fixed-zero IV** and a hard-coded key returned by the board's override of `env_aes_cbc_get_key()`.

### 2.2 Extracting clean SPL and U-Boot binaries

The MLO file has a 0x208-byte CHSETTINGS header in front; the real ARM image starts at offset `0x208` and loads at `0x402F0400`:

```python
import struct
mlo = open('MLO','rb').read()
# CHSETTINGS magic = 0x4D, total length at +12
length = struct.unpack('<I', mlo[0x208:0x20C])[0]
loadaddr = struct.unpack('<I', mlo[0x20C:0x210])[0]
spl = mlo[0x210 : 0x210 + length]
open('spl_real.bin','wb').write(spl)
```

`u-boot.img` is FIT-format. The firmware payload is aligned to `0x798` and unwraps to a 462,560-byte U-Boot 2017.09 ARM image at `0x80800000`.

### 2.3 Sliding-window key bruteforce

The AES key is *somewhere* in those two binaries as a contiguous 16-byte blob. With <600 KB total and a fast oracle (decrypt the first 64 bytes of `uboot.env[4:]`, score for printable ASCII + presence of `=`), brute forcing all 16-byte windows is trivial:

```python
from Crypto.Cipher import AES
ct = open('uboot.env','rb').read()[4:4+64]

def looks_like_env(pt):
    if b'=' not in pt[:32]: return 0
    return sum(1 for x in pt if 32 <= x < 127 or x == 0)

best = []
for binname in ['spl_real.bin','uboot_extracted.bin']:
    bin = open(binname,'rb').read()
    for off in range(len(bin)-16):
        key = bin[off:off+16]
        pt = AES.new(key, AES.MODE_CBC, b'\0'*16).decrypt(ct)
        s = looks_like_env(pt)
        if s > 50: best.append((s, binname, off, key, pt))
best.sort(reverse=True)
for s, src, o, k, p in best[:3]:
    print(f"{s} {src}@0x{o:x} key={k.hex()} pt={p[:48]}")
```

```text
64 uboot_extracted.bin@0x62be4 key=12691f2317ddfec3ff30a0a9cc451303 pt=b'arch=arm\x00args_mmc=run finduuid;...'
64 spl_real.bin@0x1540a       key=12691f2317ddfec3ff30a0a9cc451303 pt=b'arch=arm\x00args_mmc=run finduuid;...'
```

Same key in both binaries (they share the env handler). Total runtime: **~6 seconds** on a single core.

### 2.4 Decrypting the env

```python
from Crypto.Cipher import AES
import struct, zlib
raw = open('uboot.env','rb').read()
assert struct.unpack('<I', raw[:4])[0] == zlib.crc32(raw[4:]) & 0xFFFFFFFF
key = bytes.fromhex('12691f2317ddfec3ff30a0a9cc451303')
pt  = AES.new(key, AES.MODE_CBC, b'\0'*16).decrypt(raw[4:])
# parse NUL-separated key=value entries until double-NUL
```

111 env entries decoded. Two are interesting:

```text
fl4g=hackfest{env_aes_h4s_s3curity_c0nc3rns_and_1s_n0t_rec0mmend3d_f0r_use}
loadimage=mw.b 0x80000000 07 16;
          mw.b 0x80000010 cc 16;
          fatload mmc 0 0x92000000 zImage;
          aes.128 dec 0x80000000 0x92000000 0x82000000 0x1000000;
          aes.128 dec 0x80000000 0x93000000 0x83000000 0x1000000;
```

> **Flag 2:** `hackfest{env_aes_h4s_s3curity_c0nc3rns_and_1s_n0t_rec0mmend3d_f0r_use}`

Bonus: the `loadimage` script tells us **exactly** how to decrypt the next stage.

---

## 3. Flag 3 — decrypting `zImage` and the kernel

### 3.1 Reading the recipe

```
mw.b 0x80000000 07 16     # at 0x80000000 → 16 bytes of 0x07  (KEY)
mw.b 0x80000010 cc 16     # at 0x80000010 → 16 bytes of 0xcc  (red-herring IV)
aes.128 dec 0x80000000 0x92000000 0x82000000 0x1000000   # decrypt 16 MB chunk 1
aes.128 dec 0x80000000 0x93000000 0x83000000 0x1000000   # decrypt 16 MB chunk 2
```

In stock U-Boot 2017.09 (`cmd/aes.c`), the `aes` command takes `key src dst len` — **no IV argument** — and `aes_cbc_decrypt_blocks()` always uses a zero IV. The 0xcc bytes written to `0x80000010` are unused. So the actual decryption is:

- `AES-128-CBC, key=0x07×16, iv=0x00×16`
- Applied **independently** to two 16 MB chunks (each starts fresh with IV=0; *not* CBC-chained across the boundary)

### 3.2 Decryption

```python
from Crypto.Cipher import AES
ct = open('zImage','rb').read()           # 32 MB
KEY, IV = bytes([7])*16, bytes(16)
half = 0x1000000
pt = b''.join(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct[i*half:(i+1)*half]) for i in range(2))
open('zImage_dec.bin','wb').write(pt)
```

Verification — first 16 bytes:

```
0000a0e1 0000a0e1 0000a0e1 0000a0e1   # = mov r0, r0 × 4 (canonical ARM zImage stub start)
```

…and the magic at offset 0x24 is `0x016f2818` ✓.

zImage header tells us the real payload size: `end - start = 0x1569360` (22.4 MB). The remaining 9.6 MB is post-payload padding.

### 3.3 Kernel decompression

A gzip stream sits at offset `0x7318` inside the decrypted zImage. Standard `gzip.decompress()` chokes (concatenated streams + odd trailing data), but raw deflate works:

```python
import zlib
data = open('zImage_dec.bin','rb').read()
gz_off = data.find(b'\x1f\x8b\x08')
kernel = zlib.decompressobj(-15).decompress(data[gz_off+10:])
open('kernel.bin','wb').write(kernel)
# 45,599,496 bytes = Linux 5.9.16-jumpnow ARM, GCC 9.3.0, built Mon Dec 21 12:28:21 UTC 2020
```

### 3.4 Finding the flag

```text
$ grep -aoE 'hackfest\{[^}]+\}' kernel.bin
hackfest{h0w_d0_y0u_f33l_g41n1ng_r00t_acc3ss_0n_th3_dev1ce}
```

> **Flag 3:** `hackfest{h0w_d0_y0u_f33l_g41n1ng_r00t_acc3ss_0n_th3_dev1ce}`

Located inside `/home/root/flag.txt` of the embedded initramfs (see §5).

---

## 4. Flag 4 — the LUKS rootfs (and the *real* lesson)

### 4.1 Inspecting the LUKS2 volumes

```text
$ cryptsetup luksDump p2.img
Version:       2
UUID:          90a6ef90-cfaf-4739-805f-f5daa4d65892
Cipher:        aes-xts-plain64    Key size: 512 bits
Keyslot 0:     argon2i  time=4 memory=14806 KiB threads=1
               salt=eecce7f2…  AF stripes=4000 sha256
               area offset=32768  length=258048
Digest 0:      pbkdf2-sha256 iterations=15312
               digest=a1bf1d17cf6e20ef48f820256e99d9eaeeb0f20b61645c2bea... 
Data segment:  offset=16777216 (16 MB) — aes-xts-plain64, sector_size=512
```

The hidden volume in the gap (`hidden.img`) has the same structure but a different UUID, salts, and digest. Its data segment offset (`16 MB`) lands inside p2 — they share the same physical data area but with different keys. Classic deniable-encryption / decoy pattern.

The keyslot data looks well-formed (entropy 7.9993, no repeating 16-byte blocks). There is **no shortcut**: the master key is genuinely encrypted under `Argon2i(passphrase, salt, t=4, m=14806, p=1)` then AF-split.

### 4.2 What `cryptsetup luksOpen /dev/mmcblk1p2 rootfs` actually does

The init logic (see §5) calls **just that** — no `--key-file`, no piped passphrase. So at boot:

1. cryptsetup reads passphrase from `/dev/console` (interactive prompt)
2. derives `dk = argon2i(pp, salt, …)`
3. AES-XTS-decrypts the keyslot area with `dk`, AF-merges the result → master key candidate
4. validates via `pbkdf2_sha256(MK, digest_salt, 15312) == stored_digest`
5. on match: `dmsetup create rootfs` with MK as the dm-crypt cipher key

There is no auto-derivation. Without the passphrase, all you can do is brute force.

### 4.3 The brute-force path

The realistic attack on the user's machine:

```bash
# Direct LUKS attempt (Argon2i: ~1/sec/core on CPU, GPU helps a lot)
hashcat -m 29541 p2_header.luks /path/to/rockyou.txt

# Or shell loop
cat rockyou.txt | xargs -P "$(nproc)" -I{} -d '\n' bash -c '
  echo -n "$1" | cryptsetup luksOpen --test-passphrase --key-file=- p2.img 2>/dev/null \
    && echo "FOUND: $1"
' _ {}

# Or JtR with native LUKS support
python3 /usr/share/john/luks2john.py p2.img > p2.luks
john --wordlist=rockyou.txt p2.luks
```

> **Flag 4:** `hackfest{pa$$phr@se_s4v3d_1n_cle4r_t3xt?!}`

### 4.4 The lesson — read the flag literally

The flag's text isn't a meta-joke. **The system actually does store the passphrase in clear text** — just not on the device, *because the developer forgot to put it on the device*. Look at the next section.

---

## 5. The smoking gun — the embedded initramfs and `init.d/19-crypt`

The kernel was built with `CONFIG_INITRAMFS_SOURCE=""`, so at first glance there's no initramfs. But there is — it's just appended into the kernel image and not visible at the obvious offsets.

### 5.1 Locating it

`grep` for `070701` (cpio newc magic) in `kernel.bin` returns 977 matches — most are noise. The real archive is the largest contiguous parsing run that ends at `TRAILER!!!`:

```python
def parse_cpio(data, start):
    # cpio newc parser — fields are 8-char ASCII hex
    pos = start; files = []
    while pos < len(data) - 110 and data[pos:pos+6] == b'070701':
        ino  = int(data[pos+ 6:pos+14], 16)
        mode = int(data[pos+14:pos+22], 16)
        size = int(data[pos+54:pos+62], 16)
        nsz  = int(data[pos+94:pos+102], 16)        # ⚠ namesize is at +94, NOT +86
        name = data[pos+110:pos+110+nsz-1].decode(errors='replace')
        data_off = (pos + 110 + nsz + 3) & ~3
        files.append((name, mode, size, data[data_off:data_off+size]))
        pos = (data_off + size + 3) & ~3
        if name == 'TRAILER!!!': return files, pos
    return files, pos

# Try every 070701 candidate, keep the run that ends at TRAILER!!!
import re
positions = [m.start() for m in re.finditer(rb'070701', open('kernel.bin','rb').read())]
# earliest run that terminates cleanly: 0xb3a67c → 0x2af1cec — 33 MB, 976 files
```

⚠ My first attempt at this used the wrong `namesize` offset (the cpio newc format documentation gets quoted incorrectly in many places — namesize is at offset **94**, not 86). That bug made the parser stop after 1 entry.

### 5.2 What's inside

976 entries, including:
- `init` (3,753 B) — POSIX-shell init that processes `/init.d/*`
- `init.d/01-udev`, `09-lvm`, **`19-crypt`**, `90-rootfs`, `99-finish` — boot stages
- `bin/busybox.{nosuid,suid}`, `bin/bash.bash` (1 MB)
- `usr/sbin/cryptsetup`, `usr/sbin/cryptsetup-reencrypt`, `usr/sbin/veritysetup`
- `usr/lib/libcryptsetup.so.12.6.0`, `usr/lib/libcrypto.so.1.1`, …
- `home/root/flag.txt` ← flag 3 lives here

### 5.3 The `19-crypt` script — the punchline

```sh

    crypt_enabled() {
        return 0
    }

    crypt_run () {
		#sh

		cryptsetup luksOpen /dev/mmcblk1p2 rootfs
		bootparam_root="/dev/mapper/rootfs"

        return

    }

```

That's the **entire** content. Look at what's *not* there:
- No `--key-file=…` reading a hardcoded keyfile
- No `echo "secret" | cryptsetup …`
- No `--master-key-file=…` shortcut
- No environment lookup for a passphrase
- A leftover `#sh` (commented-out debug shell drop)

The boot literally blocks on `/dev/console` waiting for a human to type the secret. Which means in any deployment, the password lives **somewhere else** in clear text — runbook, deploy script, sticky note, Slack DM, the ops team's password manager. **That's the "saved in clear text"**: the secret never made it to the device, but to ship the device the developer had to write the secret down somewhere outside it.

---

## 6. Bonus: the deleted `flag4_rootfs.tar.xz`

While exploring the FAT, I noticed dozens of deleted directory entries. LFN reconstruction reveals filenames like:

```
core-image-basic-beaglebone-yocto-20210928082810.rootfs.tar.xz
flag4_rootfs.tar.xz
core-image-basic… - Copy.xz
core-image-basic… - Copy (2).xz
zImage.plain   (size 22,451,040 — the unencrypted zImage)
```

`flag4_rootfs.tar.xz` lived at cluster 434 — overwritten by the current `zImage`. Two surviving copies (clusters 13222, 27812) and one in a non-allocated cluster (8462) are recoverable via FAT chain walking. They all decompress (`lzma.decompress`) to the same 28.9 MB POSIX tar, which is the basic Yocto Poky rootfs (no flag 4 inside — but interesting forensic artifact showing what the dev's filesystem looked like before encryption).

---

## 7. Toolchain summary

```
# host: Ubuntu 24.04
apt install cryptsetup-bin john hashcat
pip install --break-system-packages pycryptodome pyfatfs fdt
```

Custom scripts written along the way:
- `parse_mbr.py` — MBR + FAT16 layout walker
- `extract_spl.py` — strips CHSETTINGS header from MLO
- `extract_fit.py` — pulls firmware payload out of u-boot.img FIT image
- `bruteforce_aes_key.py` — sliding-window AES-128-CBC key recovery on the env
- `decrypt_zimage.py` — two-chunk CBC decrypt + raw deflate of kernel
- `parse_cpio.py` — cpio newc parser (with **correct** namesize offset!)
- `crack.sh` — wrapper for shadow-then-LUKS brute force

---

## 8. Lessons / what the challenge teaches

1. **`CONFIG_ENV_AES` is broken.** Hardcoded key + zero IV + AES-CBC for a structured plaintext is trivially recoverable. It was removed from mainline U-Boot for exactly this reason. (Flag 2's name calls this out directly.)

2. **A "secure boot chain" isn't transitively secure.** Each stage looked individually fine — AES-128, AES-XTS-512, Argon2i. But the key for stage *N+1* is sitting unprotected in stage *N*'s plaintext, so the chain is only as strong as the **outermost** wrapper, which here was a one-line plaintext file.

3. **`cryptsetup luksOpen` without a key source is a deployment smell.** It guarantees that operationally the secret has to be stored in clear text *somewhere off-device* (runbook, script, password manager), and that "somewhere" is now part of your threat model whether you like it or not. Either pull the key from a TPM / secure element / remote attestation / sealed-by-PCR keyfile, or accept that the encryption-at-rest is theatre.

4. **Forensics on FAT slack pays off.** The deleted directory entries told me the entire build history (basic image → flag4 image → multiple zImage iterations), and one of the surviving cluster copies recovered an artifact that told me what the original rootfs looked like.

5. **CPIO newc field offsets are easy to get wrong.** The `c_namesize` field is at byte offset **94**, not 86. Several online references have it wrong; if your cpio parser stops after one entry, this is why.

---

## 9. Final flag table

| # | Flag |
|---|---|
| 1 | `hackfest{s3cur1ty_by_0bscur1ty_m0r3_lurk5_b3n3ath_th3_eye}` |
| 2 | `hackfest{env_aes_h4s_s3curity_c0nc3rns_and_1s_n0t_rec0mmend3d_f0r_use}` |
| 3 | `hackfest{h0w_d0_y0u_f33l_g41n1ng_r00t_acc3ss_0n_th3_dev1ce}` |
| 4 | `hackfest{pa$$phr@se_s4v3d_1n_cle4r_t3xt?!}` |

Beautifully designed challenge — each flag's *text* is itself the security lesson the stage embodies. The progression from "obscurity" → "deprecated cipher" → "you have root, now what?" → "the key isn't actually on the device" mirrors the real chain-of-trust mistakes that ship in real embedded products.

