#include <iostream>
#include  <iomanip>
#include "aes256.h"
#include <vector>
#include <array>

void printMemo(std::vector<uint8_t> s){
	for(int i=0; i<s.size(); i++){
		if(i%16==0) std::cout << " ";
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

	// std::vector<uint8_t> input(32);

	// std::array<uint8_t, 40> input;

	uint8_t* input = new uint8_t[40];

	for(int i=0; i<16; i++){
		input[i] = i*17;
		std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(input[i]);
	}
	for(int i=0; i<16; i++){
		input[i+16] = input[i];
		if((i+16)%16==0) std::cout << " ";
		std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(input[i+16]);
	}
	for(int i=0; i<8; i++){
		input[i+32] = input[i];
		if((i+32)%16==0) std::cout << " ";
		std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(input[i+32]);
	}
	// for(int i=0; i<8; i++){
	// 	input[i+40] = 0;
	// 	if((i+40)%16==0) std::cout << " ";
	// 	std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(input[i+40]);
	// }
	std::cout << "\n";

	printMemo(key);
	// printMemo(input);
	
	std::vector<uint8_t> encryptedData;
	encryptedData = aes.encrypt(input, 40, key);

	printMemo(encryptedData);

	std::vector<uint8_t> decryptedData;
	decryptedData = aes.decrypt(encryptedData, 40, key);
	printMemo(decryptedData);

	delete[] input;

	return 0;
}