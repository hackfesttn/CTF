#!/usr/local/bin/python

"""

Author : layka_#3288
Event : Hackfest 7

"""

try:
	from secret import FLAG
except ImportError:
	FLAG = b"HACKFEST{DuMmy Flag for Dummy .... test}"

import os
from Crypto.Cipher import AES
import math

BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)
LAMBDA = .314
BALANCE = 3.45

MESSAGE = """Welcome again,
Hackfest team wishes a good game, and proposes to you a way for entertainement.
Just play with us and win ... !
"""

def menu():
	MENU  = "\n==================== El Menu ====================\n"
	MENU += "Select:\n"
	MENU += " 1. New Game\n"
	MENU += " 2. Get your prize\n"
	MENU += " 3. Quit\n"
	MENU += "> "

	choice = input(MENU)
	return choice

def T2G(ciphertext, nonce):
	try:
		cipher = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
		plaintext = cipher.decrypt(ciphertext)
		assert len(plaintext) == 11
		assert plaintext[:8] == b"BALANCE:"
		balance = round(float(plaintext.split(b":")[1]), 1)
		return balance
	except:
		return 0
	
def G2T(balance):
	try:
		nonce = os.urandom(BLOCK_SIZE - 1)
		cipher = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
		plaintext = b"BALANCE:" + str(balance).encode()
		assert len(plaintext) == 11
		assert plaintext[:8] == b"BALANCE:"
		ciphertext = cipher.encrypt(plaintext)
		return ciphertext, nonce
	except:
		return b"\x00", b"\x00"

def main():
	global BALANCE
	for _ in range(3):
		try:
			choice = menu()

			if choice == "1":
				bet = float(input("Make your bet: "))
				assert 0 < bet < 11
				bet = LAMBDA / math.exp(- bet * LAMBDA)
				print("You win:", bet)
				BALANCE += bet
				BALANCE = round(BALANCE, 1)
				print("Your balance:", BALANCE)
				if BALANCE <= 0:
					print("Tga3ed!")
					exit(0)
				else:
					c, n = G2T(BALANCE)
					token = c.hex() + "." + n.hex()
					print("Here is your token:", token)
			
			elif choice == "2":
				c, n = map(bytes.fromhex, input("Submit token (hex.hex): ").split("."))
				BALANCE = T2G(c, n)
				if BALANCE > 1000000000: # You will never win hihihihi
					print("sa7it!")
					print(FLAG)
					exit(0)
				print("Your balance:", BALANCE)

			elif choice == "3":
				print("Filamen!")
				exit(0)
		
		except:
			print("Y rawa7!")
			exit(0)

	print("Y rawa7!")
		




if "__main__" == __name__ :
	main()