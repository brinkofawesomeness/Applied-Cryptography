#include <iostream>
#include <iomanip>
#include <cstdint>
#include <vector>

#include "../AES.h"
#include "../AES-Worker.h"

void AESUnitTests::Test_128_Bit_KeyExpansion() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> origKey { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c };
    bool passesAllTests = true;
    
    AES aes(plaintext, origKey, 128);
    AESWorker worker;

    std::vector <uint32_t> expandedKey { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
                                         0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
                                         0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
                                         0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
                                         0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
                                         0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
                                         0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
                                         0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
                                         0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
                                         0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
                                         0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6 
                                        };
    worker.runKeyExpansion(aes);

    if (aes.key != expandedKey) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_128_Bit_KeyExpansion: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_192_Bit_KeyExpansion() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> origKey { 0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b };
    bool passesAllTests = true;
    
    AES aes(plaintext, origKey, 192);
    AESWorker worker;

    std::vector <uint32_t> expandedKey { 0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 
                                         0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, 
                                         0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
                                         0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 
                                         0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, 
                                         0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
                                         0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, 
                                         0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 
                                         0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
                                         0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 
                                         0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, 
                                         0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
                                         0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202
                                        };
    worker.runKeyExpansion(aes);

    if (aes.key != expandedKey) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_192_Bit_KeyExpansion: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_256_Bit_KeyExpansion() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> origKey { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4 };
    bool passesAllTests = true;
    
    AES aes(plaintext, origKey, 256);
    AESWorker worker;

    std::vector <uint32_t> expandedKey { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                                         0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
                                         0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
                                         0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
                                         0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
                                         0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
                                         0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
                                         0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
                                         0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
                                         0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
                                         0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15,
                                         0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
                                         0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a,
                                         0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
                                         0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e 
                                        };
    worker.runKeyExpansion(aes);

    if (aes.key != expandedKey) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_256_Bit_KeyExpansion: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_128_Bit_Encryption() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0x00, 0x44, 0x88, 0xcc},
                                                    {0x11, 0x55, 0x99, 0xdd},
                                                    {0x22, 0x66, 0xaa, 0xee},
                                                    {0x33, 0x77, 0xbb, 0xff} };
    std::vector <uint32_t> key { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
    bool passesAllTests = true;
    
    AES aes(plaintext, key, 128);
    AESWorker worker;

    std::vector <std::vector<uint8_t> > encryptedText { {0x69, 0x6a, 0xd8, 0x70},
                                                        {0xc4, 0x7b, 0xcd, 0xb4},
                                                        {0xe0, 0x04, 0xb7, 0xc5},
                                                        {0xd8, 0x30, 0x80, 0x5a} };
    worker.runKeyExpansion(aes);
    worker.runCipherAlgorithm(aes, false);

    if (aes.state != encryptedText) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_128_Bit_Encryption: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_192_Bit_Encryption() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0x00, 0x44, 0x88, 0xcc},
                                                    {0x11, 0x55, 0x99, 0xdd},
                                                    {0x22, 0x66, 0xaa, 0xee},
                                                    {0x33, 0x77, 0xbb, 0xff} };
    std::vector <uint32_t> key { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617 };
    bool passesAllTests = true;
    
    AES aes(plaintext, key, 192);
    AESWorker worker;

    std::vector <std::vector<uint8_t> > encryptedText { {0xdd, 0x86, 0x6e, 0xec},
                                                        {0xa9, 0x4c, 0xaf, 0x0d},
                                                        {0x7c, 0xdf, 0x70, 0x71},
                                                        {0xa4, 0xe0, 0xa0, 0x91} };
    worker.runKeyExpansion(aes);
    worker.runCipherAlgorithm(aes, false);

    if (aes.state != encryptedText) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_192_Bit_Encryption: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_256_Bit_Encryption() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0x00, 0x44, 0x88, 0xcc},
                                                    {0x11, 0x55, 0x99, 0xdd},
                                                    {0x22, 0x66, 0xaa, 0xee},
                                                    {0x33, 0x77, 0xbb, 0xff} };
    std::vector <uint32_t> key { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f };
    bool passesAllTests = true;
    
    AES aes(plaintext, key, 256);
    AESWorker worker;

    std::vector <std::vector<uint8_t> > encryptedText { {0x8e, 0x51, 0xea, 0x4b},
                                                        {0xa2, 0x67, 0xfc, 0x49},
                                                        {0xb7, 0x45, 0x49, 0x60},
                                                        {0xca, 0xbf, 0x90, 0x89} };
    worker.runKeyExpansion(aes);
    worker.runCipherAlgorithm(aes, false);

    if (aes.state != encryptedText) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_256_Bit_Encryption: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_128_Bit_Decryption() 
{
    std::vector <std::vector<uint8_t> > encryptedText { {0x69, 0x6a, 0xd8, 0x70},
                                                        {0xc4, 0x7b, 0xcd, 0xb4},
                                                        {0xe0, 0x04, 0xb7, 0xc5},
                                                        {0xd8, 0x30, 0x80, 0x5a} };
    std::vector <uint32_t> key { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
    bool passesAllTests = true;
    
    AES aes(encryptedText, key, 128);
    AESWorker worker;

    std::vector <std::vector<uint8_t> > plaintext { {0x00, 0x44, 0x88, 0xcc},
                                                    {0x11, 0x55, 0x99, 0xdd},
                                                    {0x22, 0x66, 0xaa, 0xee},
                                                    {0x33, 0x77, 0xbb, 0xff} };
    worker.runKeyExpansion(aes);
    worker.runInverseCipherAlgorithm(aes, false);

    if (aes.state != plaintext) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_128_Bit_Decryption: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_192_Bit_Decryption() 
{
    std::vector <std::vector<uint8_t> > encryptedText { {0xdd, 0x86, 0x6e, 0xec},
                                                        {0xa9, 0x4c, 0xaf, 0x0d},
                                                        {0x7c, 0xdf, 0x70, 0x71},
                                                        {0xa4, 0xe0, 0xa0, 0x91} };
    std::vector <uint32_t> key { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617 };
    bool passesAllTests = true;
    
    AES aes(encryptedText, key, 192);
    AESWorker worker;

    std::vector <std::vector<uint8_t> > plaintext { {0x00, 0x44, 0x88, 0xcc},
                                                    {0x11, 0x55, 0x99, 0xdd},
                                                    {0x22, 0x66, 0xaa, 0xee},
                                                    {0x33, 0x77, 0xbb, 0xff} };
    worker.runKeyExpansion(aes);
    worker.runInverseCipherAlgorithm(aes, false);

    if (aes.state != plaintext) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_192_Bit_Decryption: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_256_Bit_Decryption() 
{
    std::vector <std::vector<uint8_t> > encryptedText { {0x8e, 0x51, 0xea, 0x4b},
                                                        {0xa2, 0x67, 0xfc, 0x49},
                                                        {0xb7, 0x45, 0x49, 0x60},
                                                        {0xca, 0xbf, 0x90, 0x89} };
    std::vector <uint32_t> key { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f };
    bool passesAllTests = true;
    
    AES aes(encryptedText, key, 256);
    AESWorker worker;

    std::vector <std::vector<uint8_t> > plaintext { {0x00, 0x44, 0x88, 0xcc},
                                                    {0x11, 0x55, 0x99, 0xdd},
                                                    {0x22, 0x66, 0xaa, 0xee},
                                                    {0x33, 0x77, 0xbb, 0xff} };
    worker.runKeyExpansion(aes);
    worker.runInverseCipherAlgorithm(aes, false);

    if (aes.state != plaintext) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_256_Bit_Decryption: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_AddRoundKey() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0x04, 0xe0, 0x48, 0x28}, 
                                                    {0x66, 0xcb, 0xf8, 0x06}, 
                                                    {0x81, 0x19, 0xd3, 0x26}, 
                                                    {0xe5, 0x9a, 0x7a, 0x4c} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.key.push_back(0xa0fafe17);
    aes.key.push_back(0x88542cb1);
    aes.key.push_back(0x23a33939);
    aes.key.push_back(0x2a6c7605);

    aes.AddRoundKey(0);
    std::vector <std::vector<uint8_t> > check { {0xa4, 0x68, 0x6b, 0x02}, 
                                                {0x9c, 0x9f, 0x5b, 0x6a}, 
                                                {0x7f, 0x35, 0xea, 0x50}, 
                                                {0xf2, 0x2b, 0x43, 0x49} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_AddRoundKey: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_asVector() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    std::vector <uint8_t> word {0x87, 0xcf, 0xd1, 0x9e};
    if (aes.asVector(0x87cfd19e) != word) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_asVector: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_asWord() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    std::vector <uint8_t> word {0x87, 0xcf, 0xd1, 0x9e};
    if (aes.asWord(word) != 0x87cfd19e) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_asWord: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_FFAddByte() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    if (aes.FFAddByte(0x57, 0x83) != 0xd4) passesAllTests = false;
    if (aes.FFAddByte(aes.FFAddByte(0x38, 0xae), 0x57) != 0xc1) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_FFAddByte: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_FFAddWord() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    if (aes.FFAddWord(0x046681e5, 0xa0fafe17) != 0xa49c7ff2) passesAllTests = false;
    if (aes.FFAddWord(aes.FFAddWord(0x2b7e1516, 0x8a84eb01), 0x01000000) != 0xa0fafe17) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_FFAddWord: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_FFMultiply() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    if (aes.FFMultiply(0x57, 0x13) != 0xfe) passesAllTests = false;
    if (aes.FFMultiply(0x83, 0x57) != 0xc1) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_FFMultiply: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_InvMixColumns() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0x04, 0xe0, 0x48, 0x28}, 
                                                    {0x66, 0xcb, 0xf8, 0x06}, 
                                                    {0x81, 0x19, 0xd3, 0x26}, 
                                                    {0xe5, 0x9a, 0x7a, 0x4c} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.InvMixColumns();
    std::vector <std::vector<uint8_t> > check { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                {0xbf, 0xb4, 0x41, 0x27}, 
                                                {0x5d, 0x52, 0x11, 0x98}, 
                                                {0x30, 0xae, 0xf1, 0xe5} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_InvMixColumns: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_InvShiftRows() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                    {0xbf, 0xb4, 0x41, 0x27}, 
                                                    {0x5d, 0x52, 0x11, 0x98}, 
                                                    {0x30, 0xae, 0xf1, 0xe5} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.InvShiftRows();
    std::vector <std::vector<uint8_t> > check { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                {0x27, 0xbf, 0xb4, 0x41}, 
                                                {0x11, 0x98, 0x5d, 0x52}, 
                                                {0xae, 0xf1, 0xe5, 0x30} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_InvShiftRows: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_InvSubBytes() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                    {0x27, 0xbf, 0xb4, 0x41}, 
                                                    {0x11, 0x98, 0x5d, 0x52}, 
                                                    {0xae, 0xf1, 0xe5, 0x30} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.InvSubBytes();
    std::vector <std::vector<uint8_t> > check { {0x19, 0xa0, 0x9a, 0xe9}, 
                                                {0x3d, 0xf4, 0xc6, 0xf8}, 
                                                {0xe3, 0xe2, 0x8d, 0x48}, 
                                                {0xbe, 0x2b, 0x2a, 0x08} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_InvSubBytes: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_MixColumns() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                    {0xbf, 0xb4, 0x41, 0x27}, 
                                                    {0x5d, 0x52, 0x11, 0x98}, 
                                                    {0x30, 0xae, 0xf1, 0xe5} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.MixColumns();
    std::vector <std::vector<uint8_t> > check { {0x04, 0xe0, 0x48, 0x28}, 
                                                {0x66, 0xcb, 0xf8, 0x06}, 
                                                {0x81, 0x19, 0xd3, 0x26}, 
                                                {0xe5, 0x9a, 0x7a, 0x4c} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_MixColumns: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_RotWord() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    std::vector <uint8_t> word {0x09, 0xcf, 0x4f, 0x3c};
    std::vector <uint8_t> check {0xcf, 0x4f, 0x3c, 0x09};

    if (aes.RotWord(word) != check) passesAllTests = false;
    if (aes.RotWord(aes.asVector(0x09cf4f3c)) != aes.asVector(0xcf4f3c09)) passesAllTests = false;
    if (aes.RotWord(aes.asVector(0x2a6c7605)) != aes.asVector(0x6c76052a)) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_RotWord: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_ShiftRows() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                    {0x27, 0xbf, 0xb4, 0x41}, 
                                                    {0x11, 0x98, 0x5d, 0x52}, 
                                                    {0xae, 0xf1, 0xe5, 0x30} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.ShiftRows();
    std::vector <std::vector<uint8_t> > check { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                {0xbf, 0xb4, 0x41, 0x27}, 
                                                {0x5d, 0x52, 0x11, 0x98}, 
                                                {0x30, 0xae, 0xf1, 0xe5} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_ShiftRows: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_SubBytes() 
{
    std::vector <std::vector<uint8_t> > plaintext { {0x19, 0xa0, 0x9a, 0xe9}, 
                                                    {0x3d, 0xf4, 0xc6, 0xf8}, 
                                                    {0xe3, 0xe2, 0x8d, 0x48}, 
                                                    {0xbe, 0x2b, 0x2a, 0x08} };
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    aes.SubBytes();
    std::vector <std::vector<uint8_t> > check { {0xd4, 0xe0, 0xb8, 0x1e}, 
                                                {0x27, 0xbf, 0xb4, 0x41}, 
                                                {0x11, 0x98, 0x5d, 0x52}, 
                                                {0xae, 0xf1, 0xe5, 0x30} };
    std::vector <std::vector<uint8_t> > state = aes.getState();
    if (state != check) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_SubBytes: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_SubWord() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    std::vector <uint8_t> word {0xcf, 0x4f, 0x3c, 0x09};
    std::vector <uint8_t> check {0x8a, 0x84, 0xeb, 0x01};

    if (aes.SubWord(word) != check) passesAllTests = false;
    if (aes.SubWord(aes.asVector(0x00102030)) != aes.asVector(0x63cab704)) passesAllTests = false;
    if (aes.SubWord(aes.asVector(0x40506070)) != aes.asVector(0x0953d051)) passesAllTests = false;
    if (aes.SubWord(aes.asVector(0x8090a0b0)) != aes.asVector(0xcd60e0e7)) passesAllTests = false;
    if (aes.SubWord(aes.asVector(0xc0d0e0f0)) != aes.asVector(0xba70e18c)) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_SubWord: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}

void AESUnitTests::Test_XTime() 
{
    std::vector <std::vector<uint8_t> > plaintext;
    std::vector <uint32_t> key;
    AES aes(plaintext, key, 128);
    bool passesAllTests = true;

    if (aes.XTime(0x57) != 0xae) passesAllTests = false;
    if (aes.XTime(0xae) != 0x47) passesAllTests = false;
    if (aes.XTime(0x47) != 0x8e) passesAllTests = false;
    if (aes.XTime(0x8e) != 0x07) passesAllTests = false;

    std::cout << std::left << std::setw(30) << "Test_XTime: ";

    if (passesAllTests) std::cout << "PASSED" << std::endl;
    else std::cout << "FAILED" << std::endl;
}