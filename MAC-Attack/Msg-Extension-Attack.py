#!/usr/bin/env python3

from ModdedSHA import SHA1
from ModdedSHA import split

# Get the deets
interceptedMAC = input("Intercepted MAC: ")
interceptedMsg = input("Intercepted msg: ")
extendedString = input("Msg extension: ")

# Construct new message bit string from intercepted msg
bitString = ""
for c in range (len(interceptedMsg)):
    bitString += '{0:08b}'.format(ord(interceptedMsg[c]))

# Pad the string, accounting for the secret length
bitString += '1'
while (len(bitString) + 128) % 512 != 448:
    bitString += '0'

# Append the message length + 128-bits to account for the secret
bitString += '{0:064b}'.format((len(interceptedMsg) * 8) + 128)

# Add the bits of the extended message
for c in range (len(extendedString)):
    bitString += '{0:08b}'.format(ord(extendedString[c]))

# Change the binary string to a hex array
bytes = split(bitString, 8)
for b in range (len(bytes)):
    bytes[b] = int(bytes[b], 2)

print("\nNew msg:", ''.join('{0:02x}'.format(b) for b in bytes))
print("\nNew MAC: " + SHA1(interceptedMAC, extendedString, len(bitString) + 128))