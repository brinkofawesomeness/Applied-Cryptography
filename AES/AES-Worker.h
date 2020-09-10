#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "Tests/AES-Unit-Tests.h"

class AESWorker {
    public:

        int modeMapper(char *mode) 
        {
            if (!strcmp(mode, "Run-Tests")) return 1;
            else if (!strcmp(mode, "FIPS-Appendix-C")) return 2;
            else if (!strcmp(mode, "Encrypt")) return 3;
            else if (!strcmp(mode, "Decrypt")) return 4;
            else return 0;
        }

        void runUnitTests() 
        {
            AESUnitTests tests;
            tests.Test_128_Bit_KeyExpansion();
            tests.Test_192_Bit_KeyExpansion();
            tests.Test_256_Bit_KeyExpansion();
            tests.Test_128_Bit_Encryption();
            tests.Test_192_Bit_Encryption();
            tests.Test_256_Bit_Encryption();
            tests.Test_128_Bit_Decryption();
            tests.Test_192_Bit_Decryption();
            tests.Test_256_Bit_Decryption();
            tests.Test_AddRoundKey();
            tests.Test_asVector();
            tests.Test_asWord();
            tests.Test_FFAddByte();
            tests.Test_FFAddWord();
            tests.Test_FFMultiply();
            tests.Test_InvMixColumns();
            tests.Test_InvShiftRows();
            tests.Test_InvSubBytes();
            tests.Test_MixColumns();
            tests.Test_RotWord();
            tests.Test_ShiftRows();
            tests.Test_SubBytes();
            tests.Test_SubWord();
            tests.Test_XTime();
        }

        std::vector <uint32_t> readKey(char* key) 
        {
            std::vector <uint32_t> data;
            std::string keyStr(key);

            if (keyStr.length() % 8 != 0) {
                std::cout << "Unsupported key length: " << keyStr.length() * 4 << std::endl;
                exit(1);
            } 

            for (unsigned int i = 0; i < keyStr.length(); i += 8) {
                std::string column = keyStr.substr(i, 8);
                uint32_t val = (uint32_t) std::stoul(column, nullptr, 16);
                data.push_back(val);
            }

            return data;
        }

        std::vector <std::vector<uint8_t> > readMsg(char* plaintext) 
        {
            std::vector <std::vector<uint8_t> > data(4, std::vector<uint8_t> (4));
            std::string textStr(plaintext);

            if (textStr.length() != 32) {
                std::cout << "Unsupported block size: " << textStr.length() << std::endl;
                exit(1);
            } 

            int row = 0, 
                col = 0;

            for (unsigned int i = 0; i < textStr.length(); i += 2) {
                std::string byteStr = textStr.substr(i, 2);
                uint8_t val = (uint8_t) std::stoul(byteStr, nullptr, 16);

                data[row][col] = val;
                
                row++;
                if (row == 4) {
                    row = 0;
                    col++;
                }
            }

            return data;
        }

        void printState(AES& aes) 
        {
            for (unsigned int col = 0; col < aes.state.size(); col++) {
                for (unsigned int row = 0; row < aes.state[col].size(); row++) {
                    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int) aes.state[row][col];
                }
            }
            std::cout << std::endl;
        }

        void printKey(AES& aes, int round) 
        {
            for (int col = 0; col < 4; col++) {
                std::cout << std::setfill('0') << std::setw(8) << std::hex << (int) aes.key[round * 4 + col];
            }
            std::cout << std::endl;
        }

        void runAppendixC() 
        {
            char* origPlaintext = (char *) "00112233445566778899aabbccddeeff";
            char* origKeys[3];
            origKeys[0] = (char *) "000102030405060708090a0b0c0d0e0f";
            origKeys[1] = (char *) "000102030405060708090a0b0c0d0e0f1011121314151617";
            origKeys[2] = (char *) "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
            std::vector <uint32_t> key;
            std::vector <std::vector<uint8_t> > plaintext;

            for (int idx = 0; idx < 3; idx++) {
                key = readKey(origKeys[idx]);
                plaintext = readMsg(origPlaintext);
                AES aes(plaintext, key, key.size() * 32);

                std::cout << "PLAINTEXT:           " << origPlaintext << std::endl;
                std::cout << "KEY:                 " << origKeys[idx] << std::endl;
                std::cout << std::endl;

                runKeyExpansion(aes);
                runCipherAlgorithm(aes, true);
                std::cout << std::endl;
                runInverseCipherAlgorithm(aes, true);

                if (idx != 2) std::cout << std::endl << std::endl;
            }
        }

        void runKeyExpansion(AES& aes) 
        {
            std::vector <uint8_t> wordArr;
            uint32_t word;
            int curr = aes.Nk;

            while (curr < aes.Nb * (aes.Nr + 1)) {
                wordArr = aes.asVector(aes.key[curr - 1]);
                
                if (curr % aes.Nk == 0) {
                    wordArr = aes.asVector(aes.asWord(aes.SubWord(aes.RotWord(wordArr))) ^ aes.Rcon[(curr / aes.Nk)]);
                } else if ((aes.Nk > 6) && (curr % aes.Nk == 4)) {
                    wordArr = aes.SubWord(wordArr);
                }

                word = aes.asWord(wordArr) ^ aes.key[curr - aes.Nk];
                aes.key.push_back(word);
                curr++;
            }
        }

        void runCipherAlgorithm(AES& aes, bool verbose) 
        {   
            if (verbose) { 
                std::cout << "CIPHER (ENCRYPT):" << std::endl;
                std::cout << "round[ 0].input      ";
                printState(aes);
                std::cout << "round[ 0].k_sch      ";
                printKey(aes, 0);
            }
            aes.AddRoundKey(0);

            for (int round = 1; round < aes.Nr; round++) {
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << round << "].start      ";
                    printState(aes);
                }

                aes.SubBytes();
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << round << "].s_box      ";
                    printState(aes);
                }

                aes.ShiftRows();
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << round << "].s_row      ";
                    printState(aes);
                }

                aes.MixColumns();
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << round << "].m_col      ";
                    printState(aes);
                }

                aes.AddRoundKey(round);
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << round << "].k_sch      ";
                    printKey(aes, round);
                }
            }

            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].start      ";
                printState(aes);
            }

            aes.SubBytes();
            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].s_box      ";
                printState(aes);
            }

            aes.ShiftRows();
            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].s_row      ";
                printState(aes);
            }

            aes.AddRoundKey(aes.Nr);
            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].k_sch      ";
                printKey(aes, aes.Nr);
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].output     ";
                printState(aes);
            }
        } 

        void runInverseCipherAlgorithm(AES& aes, bool verbose) 
        {
            if (verbose) { 
                std::cout << "INVERSE CIPHER (DECRYPT):" << std::endl;
                std::cout << "round[ 0].iinput     ";
                printState(aes);
                std::cout << "round[ 0].ik_sch     ";
                printKey(aes, aes.Nr);
            }
            aes.AddRoundKey(aes.Nr);

            for (int round = aes.Nr - 1; round > 0; round--) {
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr - round << "].istart     ";
                    printState(aes);
                }

                aes.InvShiftRows();
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr - round << "].is_row     ";
                    printState(aes);
                }

                aes.InvSubBytes();
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr - round << "].is_box     ";
                    printState(aes);
                }

                aes.AddRoundKey(round);
                if (verbose) {
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr - round << "].ik_sch     ";
                    printKey(aes, round);
                    std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr - round << "].ik_add     ";
                    printState(aes);
                }

                aes.InvMixColumns();
            }

            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].istart     ";
                printState(aes);
            }

            aes.InvShiftRows();
            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].is_row     ";
                printState(aes);
            }

            aes.InvSubBytes();
            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].is_box     ";
                printState(aes);
            }

            aes.AddRoundKey(0);
            if (verbose) {
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].ik_sch     ";
                printKey(aes, 0);
                std::cout << "round[" << std::setfill(' ') << std::setw(2) << std::dec << aes.Nr << "].ioutput    ";
                printState(aes);
            }
        }
};