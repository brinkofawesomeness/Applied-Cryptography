#include <unordered_set>

class HashAttack {
	public:
		HashAttack(int, char*);
		void doAttack(std::string, int);
	private:
		uint64_t collisionAttack(int);
		uint64_t preImageAttack(int);
		int modeMapper(std::string);
		void generateString();

		int BYTELEN;
		char *filename;
		const size_t STRLEN = 20;
		unsigned char target[20];
		std::string targetStr;
		std::string randomString;
		std::unordered_set <std::string> digests;
		std::unordered_set <std::string>::iterator it;
};
