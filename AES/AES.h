#include <cstdint>
#include <vector>

class AES {
    private: 
        // Finite field arithmetic
        uint8_t FFAddByte(uint8_t a, uint8_t b);                   // Adds two finite fields for 8 bits
        uint32_t FFAddWord(uint32_t a, uint32_t b);                // Adds two finite fields for 32 bits
        uint8_t FFMultiply(uint8_t a, uint8_t b);                  // Uses XTime() to multiply any finite field by any other finite field
        uint8_t XTime(uint8_t ff);                                 // Multiplies a finite field by x

        // Key expansion
        std::vector <uint8_t> RotWord(std::vector <uint8_t> word); 
        std::vector <uint8_t> SubWord(std::vector <uint8_t> word);   

        std::vector <uint8_t> asVector(uint32_t word);
        uint32_t asWord(std::vector <uint8_t> word);

        // Cipher functions
        void AddRoundKey(uint8_t round);
        void InvMixColumns();                                       
        void InvShiftRows();                                        
        void InvSubBytes();                                         
        void MixColumns();                                                                                    
        void ShiftRows();                                          
        void SubBytes();
        
        int Nb;      // Number of columns (32-bit words) in the state, Nb = 4
        int Nk;      // Number of 32-bit words comprising the Cipher Key, Nk = 4, 6, or 8
        int Nr;      // Number of rounds, Nr = 10, 12, or 14
        
        std::vector <uint32_t> Rcon;
        std::vector <uint32_t> key;

        std::vector <std::vector<uint8_t> > state;
        std::vector <std::vector<uint8_t> > Sbox;
        std::vector <std::vector<uint8_t> > InvSbox;

    public:
        AES( std::vector <std::vector<uint8_t> > plaintext, 
             std::vector <uint32_t> origKey,
             int keysize );
        std::vector <std::vector<uint8_t> > getState();

        friend class AESWorker;
        friend class AESUnitTests;
};