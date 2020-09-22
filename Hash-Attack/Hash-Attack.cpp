#include <openssl/sha.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <random>
#include <cstdio>
#include <string>
#include "Hash-Attack.h"

std::random_device rd;
std::mt19937_64 rng(rd());
std::uniform_int_distribution<int> dist(0, 51);

void HashAttack::doAttack(std::string mode, int sample) 
{
	switch (modeMapper(mode)) 
	{
		case 1:
			preImageAttack(sample);
			break;
		case 2:
			collisionAttack(sample);
			break;
		default:
			std::cout << "Unsupported command: try running ./Hash-Attack [Pre-Image|Collision] [Bit-Length]" << std::endl;
			exit(1);
	}
}

HashAttack::HashAttack(int len, char* file) 
{
	if (len % 8 != 0) {
		std::cout << "Bit length must be a multiple of 8." << std::endl;
		exit(1);
	}
	BYTELEN = len / 8;
	filename = file;
}

uint64_t HashAttack::collisionAttack(int sample) 
{
	uint64_t iteration = 0;
	bool successful = false;
	unsigned char hash[20];
	std::string digest;

	while (!successful) {
		generateString();
		SHA1((const unsigned char*) randomString.c_str(), STRLEN, hash);
		
		digest.clear();
		for (int i = 0; i < BYTELEN; i++) {
			digest += std::to_string(hash[i]);
		} 

		it = digests.find(digest);
		if (it == digests.end()) {
			digests.insert(digest);
			iteration += 1;
		} else {
			successful = true;
			std::cout << "Broke SHA-1 with a collision attack at iteration " << iteration << " with " << BYTELEN*8 << " bits." << std::endl;
		}
	}

	std::ofstream csv;
  	csv.open (filename, std::ofstream::out | std::ofstream::app);
	csv << sample << "," << iteration << std::endl;
	csv.close();

	return iteration;
}

uint64_t HashAttack::preImageAttack(int sample) 
{
	uint64_t iteration = 0;
	bool successful = false;
	unsigned char hash[20];
	
	generateString();
	SHA1((const unsigned char*) randomString.c_str(), STRLEN, target);
	targetStr = randomString;

	while (!successful) {
		generateString();
		SHA1((const unsigned char*) randomString.c_str(), STRLEN, hash);

		if (randomString == targetStr) { std::cout << "Found the same random string at iteration " << iteration << std::endl; }
		else if (memcmp((void *) target, (void *) hash, BYTELEN) == 0) {
			successful = true;
			std::cout << "Broke SHA-1 with a pre-image attack at iteration " << iteration << " with " << BYTELEN*8 << " bits." << std::endl;
		} else {
			iteration += 1;
		}
	}

	std::ofstream csv;
  	csv.open (filename, std::ofstream::out | std::ofstream::app);
	csv << sample << "," << iteration << std::endl;
	csv.close();

	return iteration;
}

int HashAttack::modeMapper(std::string mode) 
{
	if (mode == "Pre-Image") return 1;
	else if (mode == "Collision") return 2;
	else return 0;
}

void HashAttack::generateString() 
{
	unsigned char alphabet[52] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
						  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
						  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
						  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' }; 
	
	std::string random;
	for (int i = 0; i < STRLEN; i++) {
		random += alphabet[dist(rng)];
	}

	randomString = random;
}

int main( int argc, char** argv ) 
{
	if (argc != 3) {
		std::cout << "Unsupported command: try running ./Hash-Attack [Pre-Image|Collision] [Bit-Length]" << std::endl;
		exit(1);
	}

	char filename[512];
	sprintf(filename, "Results/%s/%s_%s.csv", argv[1], argv[1], argv[2]);

	std::ofstream csv;
  	csv.open (filename, std::ofstream::out | std::ofstream::app);
	csv << "Sample,Iterations" << std::endl;

	std::string mode (argv[1]);
	HashAttack hackr(atoi(argv[2]), filename);

	for (int run = 0; run < 50; run++) {
		hackr.doAttack(mode, run + 1);
	}

	csv.close();
	return 0;
}
