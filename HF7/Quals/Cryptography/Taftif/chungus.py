#!/usr/bin/env python3

"""

Author : layka_#3288
Event : Hackfest 7

Simulates bit-length leakage, with no noise, and exports (private key as well for debug).
Example: python3 ./chungus.py -C secp256r1 60 > sigfile.txt

"""

try:
	from secret import FLAG
except ImportError:
    FLAG = b"HACKFEST{DuMmy Flag for Dummy .... test}"

import secrets

from ecdsa import ECDSA
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes

"""
def genNonceLeak(self):
		_nonce = secrets.randbelow(self.curve.group.n)
		leak = int("0x" + "{:064x}".format(_nonce)[13:-37], 16)
		self.nonce  = Mod(_nonce, self.curve.group.n)
		return leak
"""


if __name__ == "__main__":
    
    ecdsa_signer = ECDSA("secp256r1", "sha256")
    for i in range(60):
        data = secrets.randbelow(ecdsa_signer.curve.group.n)
        data = data.to_bytes((data.bit_length() + 7) // 8, 'big')
        r, s, leak = ecdsa_signer.sign(data)
        print(data.hex(), hex(r)[2:], hex(s)[2:], leak, sep=',')
    
    key = sha256(long_to_bytes(int(ecdsa_signer.key))).digest()
    cipher = AES.new(key, mode=AES.MODE_ECB)
    print("Encrypted FLAG:", cipher.encrypt(pad(FLAG, 16)).hex())

    
