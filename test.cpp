#include <iostream>
#include  <iomanip>
#include "aes256.h"

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

	std::vector<uint8_t> input;
	for(int i=0; i<16; i++){
		input.push_back(i*17);
	}

	printMemo(input);
	printMemo(key);

	aes.encrypt(input, key);





	return 0;
}