#include "aes256.h"
#include <cstdint>

void AES256::addRoundKey(uint8_t& state, uint8_t& rndKey){
	for(size_t i=0; i<stSz; i++){
		state[i] = state[i] ^ rndKey[i];
	}
}

void AES256::keyExpansion(uint8_t& cphKey, uint32_t& expKey){
	
}

void AES256::subBytes(void){

}

void AES256::shiftRows(void){

}

void AES256::mixColumns(void){

}

void AES256::encrypt(uint8_t& buffer, size_t sz, uint8_t& key){
	keyExpansion();
}

void AES256::decrypt(uint8_t& buffer, uint8_t& key){

}


