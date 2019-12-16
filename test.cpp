#include <iostream>
#include "aes256.h"

void printMemo(std::vector<uint8_t> s){
	for(int i=0; i<s.size(); i++){
		std::cout << std::hex << static_cast<int>(s[i]);
	}
	std::cout<<"\n";
}

int main(){

	AES256 aes;

	std::vector<uint8_t> key(64);
	key = aes.keyGen();

	std::vector<uint8_t> input;
	for(int i=0; i<16; i++){
		input.push_back(i);
	}

	aes.encrypt(input, key);




	return 0;
}