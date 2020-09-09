#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>

#include "AES.h"
#include "AES-Worker.h"

int main(int argc, char *argv[]) {

    std::vector <std::vector<uint8_t> > block;
    std::vector <uint32_t> origKey;
    AESWorker worker;
    AES* aes;

    char* mode = nullptr;
    if (argc == 2 || argc == 4) mode = argv[1];
    else {
        if (argc < 4) std::cout << "Not enough arguments. ";
        else if (argc > 4) std::cout << "Too many arguments. ";
        std::cout << "Usage> ./AES-Worker Run-Tests|FIPS-Appendix-C|Encrypt|Decrypt [PLAINTEXT] [KEY]" << std::endl;
        exit(1);
    }

    switch (worker.modeMapper(mode)) 
    {
        case 1:
            worker.runUnitTests();
            break;
        case 2:
            worker.runAppendixC();
            break;
        case 3:
            if (argc < 4) {
                std::cout << "Please include a 128 bit block and a 128|192|256 bit key." << std::endl;
                exit(1);
            }
            block = worker.readMsg(argv[2]);
            origKey = worker.readKey(argv[3]);
            aes = new AES(block, origKey, origKey.size() * 32);
            worker.runKeyExpansion(*aes);
            worker.runCipherAlgorithm(*aes, false);
            worker.printState(*aes);
            break;
        case 4:
            if (argc < 4) {
                std::cout << "Please include a 128 bit block and a 128|192|256 bit key." << std::endl;
                exit(1);
            }
            block = worker.readMsg(argv[2]);
            origKey = worker.readKey(argv[3]);
            aes = new AES(block, origKey, origKey.size() * 32);
            worker.runKeyExpansion(*aes);
            worker.runInverseCipherAlgorithm(*aes, false);
            worker.printState(*aes);
            break;
        default: 
            std::cout << "Unsupported command. Usage> ./AES-Worker Run-Tests|FIPS-Appendix-C|Encrypt|Decrypt [PLAINTEXT] [KEY]" << std::endl;
    }
    
    return 0;
}