#!/usr/bin/env python3

from Crypto.Util import number

# Modular exponentiation
def modExp(g, a, p):
    binaryStr = bin(a)[2:]
    val = 1
    for b in range(len(binaryStr)):
        if binaryStr[b] == '1':
            val *= pow(g, 2 ** (len(binaryStr) - b - 1), p)
    return val % p

# Greatest common divisor
def gcd(a, b):
    while (b):
        temp = a
        a = b
        b = temp % b
    return a

# Extended Euclidean algorithm
def extEuclidean(a, b):
    y = prevX = 1
    x = prevY = 0
    while (b):
        q = a // b      # Keep track of quotients
        
        temp = x
        x = prevX - (q * x)
        prevX = temp
        
        temp = y
        y = prevY - (q * y)
        prevY = temp
        
        temp = a        # Euclidean algorithm
        a = b
        b = temp % b

    return prevY

# Checks if the highest order bit is 1
def highOrderBitSet(num):
    if (1 & (num >> 511)):
        return True
    else:
        return False

# Verifies if two numbers are relatively prime with their GCD
def relativelyPrime(a, b):
    if (gcd(a, b) == 1):
        return True
    else:
        return False

# Constant
e = 65537

# Generate two strong 512-bit primes
p = number.getPrime(512)
q = number.getPrime(512)
phi = (p - 1) * (q - 1)

# Verify that they are secure
while (not highOrderBitSet(p) or not highOrderBitSet(q) or not relativelyPrime(phi, e)):
    p = number.getPrime(512)
    q = number.getPrime(512)
    phi = (p - 1) * (q - 1)

# Calculate secret exponent d
n = p * q
d = extEuclidean(phi, e) % phi

# Check its validity
if (e * d) % phi != 1 or gcd(e, phi) != 1:
    print("Something went wrong here :/")

else:
    # Print out the values
    print("p: " + str(p))
    print("\nq: " + str(q))
    print("\nn: " + str(n))
    print("\nd: " + str(d))
    
    # Encrypt/decrypt values
    plaintext = input("\nTo encrypt: ")
    ciphertext = modExp(int(plaintext, 10), e, n)
    print("\nCiphertext: " + str(ciphertext))

    ciphertext = input("\nTo decrypt: ")
    plaintext = modExp(int(ciphertext, 10), d, n)
    print("\nPlaintext: " + str(plaintext))

# Destroy p and q
p = q = 0