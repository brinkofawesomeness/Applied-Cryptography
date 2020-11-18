#!/usr/bin/env python3

import hashlib
import random
import math

# Define the data structures
class Block:
    def __init__(self, quote, nonce, hashVal):
        self.quote = quote
        self.nonce = nonce
        self.hash = hashVal

Quotechain = []

# Determine if the first 10 bits are 0
# Used for proof of work
def isHashValid(hashVal):
    hexDigest = hashVal.hexdigest()
    if (hexDigest[0] == '0' and 
        hexDigest[1] == '0' and 
        hexDigest[2] <= '3'): 
        return True
    else: 
        return False

# Get initial hash from genesis block
prevHash = input("Initial block hash: ")
prevHash = int(prevHash, base=16).to_bytes(32, byteorder="big")

# Appending to the ledger
while (True):

    # Get previous hash
    if (len(Quotechain) != 0):
        prevHash = Quotechain[len(Quotechain) - 1].hash.hexdigest()
        prevHash = int(prevHash, base=16).to_bytes(32, byteorder="big")

    # Business logic
    quote = input("Enter new quote: ")
    if (quote == "Done"):
        break

    # Convert quote to bytes
    quoteBytes = bytes(quote, encoding="ascii")

    # Proof of work
    while (True):
        nonce = random.SystemRandom().getrandbits(64)
        nonceBytes = nonce.to_bytes(8, byteorder="big")
        hashVal = hashlib.sha256(prevHash + nonceBytes + quoteBytes)
        if (isHashValid(hashVal)):
            break

    # Add the block to the blockchain
    block = Block(quote, nonce, hashVal)
    Quotechain.append(block)

    # Print
    print("\nNonce: " + str(block.nonce))
    print("Hash: " + block.hash.hexdigest() + "\n")