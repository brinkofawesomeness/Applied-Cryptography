class AESUnitTests {
    private:
    public:
        // AES Worker
        void Test_128_Bit_KeyExpansion();
        void Test_192_Bit_KeyExpansion();
        void Test_256_Bit_KeyExpansion();
        void Test_128_Bit_Encryption();
        void Test_192_Bit_Encryption();
        void Test_256_Bit_Encryption();
        void Test_128_Bit_Decryption();
        void Test_192_Bit_Decryption();
        void Test_256_Bit_Decryption();

        // AES
        void Test_AddRoundKey();
        void Test_asVector();
        void Test_asWord();
        void Test_FFAddByte();
        void Test_FFAddWord();
        void Test_FFMultiply();
        void Test_InvMixColumns();
        void Test_InvShiftRows();
        void Test_InvSubBytes();
        void Test_MixColumns();
        void Test_RotWord();
        void Test_ShiftRows();
        void Test_SubBytes();
        void Test_SubWord();
        void Test_XTime();
};