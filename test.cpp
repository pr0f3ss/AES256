#include <iostream>
#include  <iomanip>
#include "aes256.h"
#include <vector>
#include <array>

void printMemo(std::vector<uint8_t> s){
	for(int i=0; i<s.size(); i++){
		std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(s[i]);
	}
	std::cout<<"\n";
}

int main(){
	AES256 aes;

	std::vector<uint8_t> key(32);
	for(int i=0; i<32; i++){
		key[i] = i;
	}

	// std::vector<uint8_t> input;
	// for(int i=0; i<16; i++){
	// 	input.push_back(i*17);
	// }

	// std::array<uint8_t, 16> input;
	// for(int i=0; i<16; i++){
	// 	input[i] = i*17;
	// }
	uint8_t input[16];
	for(int i=0; i<16; i++){
		input[i] = i*17;
	}


	printMemo(key);
	
	std::vector<uint8_t> encryptedData;
	encryptedData = aes.encrypt(input, key);

	printMemo(encryptedData);

	std::vector<uint8_t> decryptedData;
	decryptedData = aes.decrypt(encryptedData, key);
	printMemo(decryptedData);


	return 0;
}