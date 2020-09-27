#!/usr/bin/env python3

# Define splitting a string into equal blocks
def split(string, blockLength):
    return [string[i:i+blockLength] for i in range (0, len(string), blockLength)]

# Define custom SHA-1 algorithm to inject intermediate 
# steps for a message extension attack
def SHA1(MAC, extendedMsg, length):
# def SHA1(preImage):

    def rotl(word, n):
        return ((word << n) | (word >> (32 - n))) & 0xFFFFFFFF

    # Set the magic numbers to the old MAC
    startingPoint = split(MAC, 8)
    h0 = int(startingPoint[0], 16)
    h1 = int(startingPoint[1], 16)
    h2 = int(startingPoint[2], 16)
    h3 = int(startingPoint[3], 16)
    h4 = int(startingPoint[4], 16)

    # Convert the pre-image into a bit string
    bitString = ""
    for c in range (len(extendedMsg)):
        bitString += '{0:08b}'.format(ord(extendedMsg[c]))

    # Pad the string
    bitString += '1'
    while len(bitString) % 512 != 448:
        bitString += '0'

    # Append the message length
    bitString += '{0:064b}'.format(length)

    # Break up the bit string into 512-bit blocks
    for block in split(bitString, 512):

        # Break chunk into 16 32-bit words
        words = split(block, 32)

        # Extend the words into 80 32-bit words
        for w in range (0, 16):
            words[w] = int(words[w], 2)
        for w in range (16, 80):
            words.append(rotl(words[w-3] ^ words[w-8] ^ words[w-14] ^ words[w-16], 1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for i in range (0, 80): 
            if 0 <= i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = rotl(a, 5) + f + e + k + words[i] & 0xFFFFFFFF
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = temp

        h0 = h0 + a & 0xFFFFFFFF
        h1 = h1 + b & 0xFFFFFFFF
        h2 = h2 + c & 0xFFFFFFFF
        h3 = h3 + d & 0xFFFFFFFF
        h4 = h4 + e & 0xFFFFFFFF

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)