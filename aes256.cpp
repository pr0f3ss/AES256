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
#include <iomanip>
#include <cassert>
#include <stdexcept>

void printMem(std::vector<uint8_t> s){
	for(int i=0; i<s.size(); i++){
		//if(i%4==0) std::cout << "\n";
		std::cout <<  std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(s[i]);

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

// tested
template<class Iterator> void AES256::addRoundKey(Iterator w){
	auto itSt = stBlk.begin();
	for(size_t i=0; i<Nb; i++, w++){
		uint32_t tmp = 0;
		size_t j=0;
		do{
			tmp <<= 8;
			tmp = ((*itSt++)|tmp);
			j++;
		}while(j<4);

		itSt--;

		tmp ^= *w;
		for(j=0; j<4; j++, tmp>>=8){
			*itSt-- = tmp;
		}
		itSt+=5;
	}
	return;
}

// tested
void AES256::fillRcon(){
	uint32_t rc = 1, rcL = 1;
	for(size_t i=0; i<RconSz; i++){
		Rcon[i] = rc<<24;
		rc = rcL<80 ? 2*rcL : (2*rcL)^0x1B;
		rcL = rc;
	}
	return;
}

// for encryption mix columns fast for polynomials b of form x and x+1
uint8_t AES256::galoisMult(uint8_t a, uint8_t b){
	assert(b==2 || b==3);
	if(b==2){
		return ((a<<1) ^ ((a&0x80) ? 0x1B : 0x00));
	}else{
		return galoisMult(a,2)^a;
	}
}

// for large polynomials (b > x+1)
uint8_t AES256::galoisMultL(uint8_t a, uint8_t b){
	uint8_t p = 0, c, i;
	for(i=0; i<8; i++){
		if((b&1)==0x01)	p^=a;
		c = a&0x80;
		a<<=1;
		if(c==0x80)	a^=0x1B;
		b>>=1;
	}
	return p;
}


// tested
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

// tested
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

// tested
void AES256::subBytes(void){
	for(size_t i=0; i<stSz; i++){
		stBlk[i] = SBox[16*(stBlk[i]>>4)+(stBlk[i]&0xF)];
	}
}

// tested
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
	return;
}

// tested, todo: optimization
void AES256::mixColumns(void){
	std::array<uint8_t, 4> fetch;
	for(size_t i=0; i<Nb; i++){
		size_t idx = i*4;
		for(size_t j=0; j<4; j++){
				fetch[j] = stBlk[idx+j];
			}
		
		stBlk[idx] = galoisMult(fetch[0], 0x02) ^ galoisMult(fetch[1], 0x03) ^ fetch[2] ^ fetch[3];
		stBlk[idx+1] = fetch[0] ^ galoisMult(fetch[1], 0x02) ^ galoisMult(fetch[2], 0x03) ^ fetch[3];
		stBlk[idx+2] = fetch[0] ^ fetch[1] ^ galoisMult(fetch[2], 0x02) ^ galoisMult(fetch[3], 0x03);
		stBlk[idx+3] = galoisMult(fetch[0], 0x03) ^ fetch[1] ^ fetch[2] ^ galoisMult(fetch[3], 0x02);
	}
	return;
}


void AES256::invSubBytes(void){
	for(size_t i=0; i<stSz; i++){
		stBlk[i] = RSBox[16*(stBlk[i]>>4)+(stBlk[i]&0xF)];
	}
}

void AES256::invShiftRows(void){
	std::array<uint8_t, 4> fetch;
	for(int i=1; i<4; i++){
		for(int j=0; j<i; j++){
			for(size_t k=0; k<4; k++){
				fetch[k] = stBlk[i+4*k];
			}
			for(size_t k=0; k<4; k++){
				stBlk[(((i+4*k)+4)%stSz)] = fetch[k];
			}
		}
	}
}

void AES256::invMixColumns(void){
	std::array<uint8_t, 4> fetch;
	for(size_t i=0; i<Nb; i++){
		size_t idx = i*4;
		for(size_t j=0; j<4; j++){
				fetch[j] = stBlk[idx+j];
		}
		
		stBlk[idx] 	 = galoisMultL(fetch[0], 0x0E) ^ galoisMultL(fetch[1], 0x0B) ^ galoisMultL(fetch[2], 0x0D) ^ galoisMultL(fetch[3], 0x09);
		stBlk[idx+1] = galoisMultL(fetch[0], 0x09) ^ galoisMultL(fetch[1], 0x0E) ^ galoisMultL(fetch[2], 0x0B) ^ galoisMultL(fetch[3], 0x0D);
		stBlk[idx+2] = galoisMultL(fetch[0], 0x0D) ^ galoisMultL(fetch[1], 0x09) ^ galoisMultL(fetch[2], 0x0E) ^ galoisMultL(fetch[3], 0x0B);
		stBlk[idx+3] = galoisMultL(fetch[0], 0x0B) ^ galoisMultL(fetch[1], 0x0D) ^ galoisMultL(fetch[2], 0x09) ^ galoisMultL(fetch[3], 0x0E);
	}
	return;
}


// tested
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
	size_t sz = in.size();
	size_t pad = stSz - (sz%stSz);
	size_t actSz = sz+pad;
	size_t amtBlk = (actSz)/stSz;
	std::vector<uint8_t> stOut(actSz);

	cpyKey(key.begin(), key.end());
	
	keyExpansion();

	for(size_t i=0; i<amtBlk; i++){
		auto itSt = stBlk.begin();
		std::fill(itSt, stBlk.end(), static_cast<uint8_t>(pad));

		auto itIn = in.begin()+(i*stSz);
		auto itInEnd = itIn+stSz;
		while(itIn!=in.end()&&itIn!=itInEnd){
			*itSt++ = *itIn++;
		}

		encipher();

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
	size_t pad = stSz - (sz%stSz);
	size_t actSz = sz+pad;
	size_t amtBlk = (actSz)/stSz;
	std::vector<uint8_t> stOut(actSz);

	cpyKey(key.begin(), key.end());
	
	keyExpansion();

	for(size_t i=0; i<amtBlk; i++){
		auto itSt = stBlk.begin();
		std::fill(itSt, stBlk.end(), static_cast<uint8_t>(pad));

		size_t idx = i*stSz;
		size_t idxEnd = idx+stSz;
		while(idx<sz&&idx<idxEnd){
			*itSt++ = in[idx];
			idx++;
		}

		encipher();

		itSt = stBlk.begin();
		auto itOut = stOut.begin()+(i*stSz);
		while(itSt!=stBlk.end()){
			*itOut++ = *itSt++;
		}
	}
	return stOut;
}


/* 
	DECRYPTION
*/

std::vector<uint8_t> AES256::decrypt(const std::vector<uint8_t>& in, std::vector<uint8_t> key){
	if(in.size()%stSz!=0) throw std::length_error("Size of input data is not aligned to 16 bytes");
	std::vector<uint8_t> stOut(in.size());
	cpyKey(key.begin(), key.end());
	bool aligned = in.size()%stSz==0;
	size_t amtBlk = aligned ? in.size()/stSz : (in.size()/stSz)+1;
	keyExpansion();

	for(size_t i=0; i<amtBlk; i++){
		auto itSt = stBlk.begin();
		std::fill(itSt, stBlk.end(), 0);

		auto itIn = in.begin()+(i*stSz);
		auto itInEnd = itIn+stSz;
		while(itIn!=in.end()&&itIn!=itInEnd){
			*itSt++ = *itIn++;
		}

		decipher();

		itSt = stBlk.begin();
		auto itOut = stOut.begin()+(i*stSz);
		while(itSt!=stBlk.end()){
			*itOut++ = *itSt++;
		}
	}

	return stOut;
}

std::vector<uint8_t> AES256::decrypt(const std::vector<uint8_t>& in, size_t initSz, std::vector<uint8_t> key){
	std::vector<uint8_t> decData(decrypt(in, key));
	std::vector<uint8_t> stOut(initSz);
	std::copy(decData.begin(), decData.begin()+initSz, stOut.begin());
	return stOut;
}

// tested
void AES256::encipher(void){
	addRoundKey(expKey.begin());

	for(size_t i=0; i<Nr-1; i++){
		subBytes();
		shiftRows();
		mixColumns();
		addRoundKey(expKey.begin()+((i+1)*Nb));
	}

	subBytes();
	shiftRows();
	addRoundKey(expKey.begin()+(Nr*Nb));
}

void AES256::decipher(void){
	addRoundKey(expKey.begin()+(Nr*Nb));

	for(size_t i=Nr-1; i>=1; i--){
		invShiftRows();
		invSubBytes();
		addRoundKey(expKey.begin()+(i*Nb));
		invMixColumns();
	}

	invShiftRows();
	invSubBytes();
	addRoundKey(expKey.begin());
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

