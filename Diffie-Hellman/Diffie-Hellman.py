#!/usr/bin/env python3

import math
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.Util.Padding import unpad

# Modular exponentiation
def modExp(g, a, p):
    binaryStr = bin(a)[2:]
    val = 1
    for b in range(len(binaryStr)):
        if binaryStr[b] == '1':
            val *= pow(g, (len(binaryStr) - b - 1), p)
    return val % p

# Generate a cryptographically strong 1024-bit prime
prime = number.getPrime(1024)
while not number.isPrime((prime - 1) // 2):
    prime = number.getPrime(1024)

# Randomly select our private key
privateKey = random.SystemRandom().randrange(prime)

# Compute our public key
publicKey = modExp(5, privateKey, prime)
print("Prime number (p): " + str(prime) + "\n")
print("Public key (g^a % p): " + str(publicKey) + "\n")

# Get server's public key and calculate gab
serverKey = input("Input server's public key: ")
gab = modExp(int(serverKey), privateKey, prime)

# Calculate symmetric key
gabBytes = gab.to_bytes(math.ceil(gab.bit_length() / 8), byteorder='big')
key = hashlib.sha256(gabBytes).digest()[0:16]

# Get the IV
iv = input("\nInput IV: ")
iv = int(iv, 16)
ivBytes = iv.to_bytes(16, byteorder='big')
cipher = AES.new(key, AES.MODE_CBC, ivBytes)

# Decrypt with our key
hexcipher = input("\nInput ciphertext: ")
ciphertext = bytearray.fromhex(hexcipher)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("\nPlaintext: " + plaintext.decode('utf-8'))