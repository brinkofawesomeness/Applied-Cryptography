#!/usr/bin/env python3

import math
import random
import hashlib

# Get server's info
g = int( input("Server's g value: ") )
p = int( input("Server's p value: ") )

# Randomly select our private key (a)
a = random.SystemRandom().getrandbits(1024)

# Compute our public key
publicKey = pow(g, a, p)
print("\nPublic key: " + str(publicKey) + "\n")

# Get server's password and salt
password = input("Server's password: ")
salt = input("Server's salt: ")
saltLength = math.ceil(len(salt) / 2)

# Convert to bytes and concatenate
password = bytes(password, encoding="ascii")
salt = int(salt, base=16).to_bytes(saltLength, byteorder="big")

# Concatenate them and hash
x = hashlib.sha256(salt + password)
for i in range (999):
    x = hashlib.sha256(x.digest())
print("\nx: " + str(int(x.hexdigest(), base=16)))

# Compute k = H(p || g)
p_bytes = int(p).to_bytes(math.ceil(p.bit_length() / 8), byteorder="big")
g_bytes = int(g).to_bytes(math.ceil(g.bit_length() / 8), byteorder="big")
pg = p_bytes + g_bytes
k = int(hashlib.sha256(pg).hexdigest(), base=16)
print("k: " + str(k))

# Get server's B_bar value
B_bar = int( input("\nServer's B value: ") )

# Calculate server's public key (g^b = B_bar - k * g^x(mod p))
serverKey = (B_bar - k * pow(g, int(x.hexdigest(), base=16), p)) % p
print("\nServer's public key: " + str(serverKey))

# Calculate u = H(g^a || g^b)
ga = publicKey.to_bytes(math.ceil(publicKey.bit_length() / 8), byteorder="big")
gb = serverKey.to_bytes(math.ceil(serverKey.bit_length() / 8), byteorder="big")
u = int(hashlib.sha256(ga + gb).hexdigest(), base=16)
print("\nu: " + str(u))

# Calculate shared key ((g^b)^a+u*x (mod p))
sharedKey = pow(serverKey, a + u * int(x.hexdigest(), base=16), p)
print("\nShared key: " + str(sharedKey))

# Calculate the zero-knowledge proof of client's password
Hp = int(hashlib.sha256(p_bytes).hexdigest(), base=16)
Hg = int(hashlib.sha256(g_bytes).hexdigest(), base=16)
pg = (Hp ^ Hg).to_bytes(math.ceil(Hp.bit_length() / 8), byteorder="big")

netId = bytes("cbrinkl4", encoding="ascii")
HnetId = int(hashlib.sha256(netId).hexdigest(), base=16).to_bytes(math.ceil(256 / 8), byteorder="big")

sharedKey = sharedKey.to_bytes(math.ceil(sharedKey.bit_length() / 8), byteorder="big")
m1 = hashlib.sha256(pg + HnetId + salt + ga + gb + sharedKey)
print("\nM1: " + str(m1.hexdigest()))

# Calculate the zero-knowledge proof of server's verifier
m2 = hashlib.sha256(ga + m1.digest() + sharedKey).hexdigest()
print("\nM2: " + str(m2))