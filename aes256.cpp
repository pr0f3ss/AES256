#include "aes256.h"
#include <cstdint>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <iterator>
#include <functional>
#include <random>
#include <array>
#include <iostream>

void printMem(std::vector<uint8_t> s){
	for(int i=0; i<s.size(); i++){
		if(i%4==0) std::cout << "\n";
		std::cout << std::hex << static_cast<int>(s[i]);

	}
	std::cout<<"\n";
}

void printMem(std::vector<uint32_t> s){
	for(int i=0; i<s.size(); i++){
		std::cout << std::hex << s[i];
	}
	std::cout<<"\n";
}

AES256::AES256(void) : cKey(kSz/8,0), stBlk(blkSz/8,0), expKey(Nb*(Nr+1)), Rcon(RconSz){
	fillRcon();
}

AES256::~AES256(void){
}


template<class Iterator> void AES256::addRoundKey(Iterator w){
	auto itSt = stBlk.begin();
	for(size_t j=0; j<Nb; j++, w++){
		for(size_t i=0; i<4; i++){
			*(itSt++) ^= *w;
		}
	}
	return;
}

void AES256::fillRcon(){
	uint32_t rc = 1, rcL = 1;
	for(size_t i=0; i<RconSz; i++){
		Rcon[i] = rc<<24;
		rc = rcL<80 ? 2*rcL : (2*rcL)^0x1B;
		rcL = rc;
	}
	return;
}

void AES256::keyExpansion(void){
	uint32_t tmp;
	auto itKey = cKey.begin();
	for(size_t i=0; i<Nk; i++){
		tmp = 0;
		size_t j=0;
		do{
			tmp <<= 8;
			tmp = ((*itKey++)|tmp);
			j++;
		}while(j<4);
		expKey[i] = tmp;
	}

	for(size_t i=Nk; i<(Nb*(Nr+1)); i++){
		tmp =  expKey[i-1];
		if(i%Nk==0){
			tmp = subWord(RotL(tmp,8))^Rcon[(i/Nk)-1];
		}else if(Nk>6 && i%Nk==4){
			tmp = subWord(tmp);
		}
		expKey[i] = expKey[i-Nk]^tmp;
	}
	return;
}


uint32_t AES256::subWord(uint32_t w){
	uint32_t out = 0;
	uint32_t map = 0xFF;
	for(size_t i=0; i<4; i++){
		uint32_t c = w&map;
		c>>=(i*8);
		out = out|SBox[16*(c>>4)+(c&0xF)];
		out = RotR(out, 8);
		map<<=0x8;
	}
	return out;
}

void AES256::subBytes(void){
	for(size_t i=0; i<stSz; i++){
		stBlk[i] = SBox[16*(stBlk[i]>>4)+(stBlk[i]&0xF)];
	}
}

void AES256::shiftRows(void){
	std::array<uint8_t, 4> fetch;
	for(int i=1; i<4; i++){
		for(int j=0; j<i; j++){
			for(size_t k=0; k<4; k++){
				fetch[k] = stBlk[i+4*k];
			}
			for(size_t k=0; k<4; k++){
				stBlk[(((i+4*k)-4)%stSz)] = fetch[k];
			}
		}
	}
}

void AES256::mixColumns(void){

}


template<class Iterator> void AES256::cpyKey(Iterator first, Iterator last){
	auto itFill = cKey.begin();
	auto itKey = first;
	while(first!=last && first!=(itKey+32)){
		*itFill++ = *first++;
	}
	return;
}

// for std::vector
std::vector<uint8_t> AES256::encrypt(const std::vector<uint8_t>& in, std::vector<uint8_t> key){
	std::vector<uint8_t> stOut(in.size());
	cpyKey(key.begin(), key.end());
	size_t amtBlk = in.size()%stSz==0 ? in.size()/stSz : (in.size()/stSz)+1;
	keyExpansion();

	for(size_t i=0; i<amtBlk; i++){
		auto itSt = stBlk.begin();
		std::fill(itSt, stBlk.end(), 0);

		auto itIn = in.begin()+(i*stSz);
		auto itInEnd = itIn+stSz;
		while(itIn!=in.end()&&itIn!=itInEnd){
			*itSt++ = *itIn++;
		}

		printMem(stBlk);
		
		shiftRows();

		//encipher();

		printMem(stBlk);

		itSt = stBlk.begin();
		auto itOut = stOut.begin()+(i*stSz);
		while(itSt!=stBlk.end()){
			*itOut++ = *itSt++;
		}
	}

	return stOut;

}

// for c-type arrays
std::vector<uint8_t> AES256::encrypt(const uint8_t* in, size_t sz, std::vector<uint8_t> key){
}


// std::vector<uint8_t> AES256::encrypt(const std::array<uint8_t>& in, std::vector<uint8_t> key){
// }

std::vector<uint8_t> AES256::decrypt(uint8_t* buffer, std::vector<uint8_t> key){

}


void AES256::encipher(void){
	addRoundKey(expKey.begin());

	for(size_t i=0; i<Nr-1; i++){
		subBytes();
		shiftRows();
		mixColumns();
		addRoundKey(expKey.begin()+(i*Nb));
	}

	subBytes();
	shiftRows();
	addRoundKey(expKey.begin()+(Nr*Nb));
}

void AES256::decipher(void){

}

std::vector<uint8_t> AES256::keyGen(void){
	size_t keySize = kSz/8;
	std::vector<uint8_t> key(keySize);
	std::random_device rnd_device;
    std::mt19937 mersenne_engine {rnd_device()};
    std::uniform_int_distribution<int> dist {0, 255};
    auto gen = [&dist, &mersenne_engine](){
                   return dist(mersenne_engine);
    };
    std::generate(key.begin(), key.end(), gen);
	return key;
}

