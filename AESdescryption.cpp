#include "AESdescryption.h"



bool AESdescryption::checkCPUsupport()
{
	int cpuInformation[4];
	__cpuid(cpuInformation, 1);
	return (cpuInformation[2] & 0x2000000);
}

void AESdescryption::loadKey(const int8_t cipherKey[])
{
	this->cipherKey = _mm_loadu_si128((__m128i*) cipherKey);
	AESdescryption::keyExpansion(this->cipherKey, this->roundKey);
}

void AESdescryption::loadCiphertext(const int8_t ciphertext[])
{
	this->ciphertext = _mm_loadu_si128((__m128i*) ciphertext);
}

void AESdescryption::descryption()
{
	this->plaintext = _mm_xor_si128(this->ciphertext, this->roundKey[10]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[11]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[12]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[13]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[14]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[15]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[16]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[17]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[18]);
	this->plaintext = _mm_aesdec_si128(this->plaintext, this->roundKey[19]);
	this->plaintext = _mm_aesdeclast_si128(this->plaintext, this->roundKey[0]);
}

AESdescryption::AESdescryption()
{

}


AESdescryption::~AESdescryption()
{
}

__m128i AESdescryption::keyExpansionModule(const __m128i key, __m128i assistantKey)
{
	__m128i tmp = key;
	assistantKey = _mm_shuffle_epi32(assistantKey, _MM_SHUFFLE(3, 3, 3, 3));
	assistantKey = _mm_xor_si128(assistantKey, tmp);
	tmp = _mm_slli_si128(tmp, 4);
	assistantKey = _mm_xor_si128(assistantKey, tmp);
	tmp = _mm_slli_si128(tmp, 4);
	assistantKey = _mm_xor_si128(assistantKey, tmp);
	tmp = _mm_slli_si128(tmp, 4);
	assistantKey = _mm_xor_si128(assistantKey, tmp);
	return assistantKey;
}

void AESdescryption::keyExpansion(const __m128i cipherKey, __m128i roundKey[])
{
	roundKey[0] = cipherKey;
	roundKey[1] = AESdescryption::keyExpansionModule(roundKey[0], _mm_aeskeygenassist_si128(roundKey[0], 0x01));
	roundKey[2] = AESdescryption::keyExpansionModule(roundKey[1], _mm_aeskeygenassist_si128(roundKey[1], 0x02));
	roundKey[3] = AESdescryption::keyExpansionModule(roundKey[2], _mm_aeskeygenassist_si128(roundKey[2], 0x04));
	roundKey[4] = AESdescryption::keyExpansionModule(roundKey[3], _mm_aeskeygenassist_si128(roundKey[3], 0x08));
	roundKey[5] = AESdescryption::keyExpansionModule(roundKey[4], _mm_aeskeygenassist_si128(roundKey[4], 0x10));
	roundKey[6] = AESdescryption::keyExpansionModule(roundKey[5], _mm_aeskeygenassist_si128(roundKey[5], 0x20));
	roundKey[7] = AESdescryption::keyExpansionModule(roundKey[6], _mm_aeskeygenassist_si128(roundKey[6], 0x40));
	roundKey[8] = AESdescryption::keyExpansionModule(roundKey[7], _mm_aeskeygenassist_si128(roundKey[7], 0x80));
	roundKey[9] = AESdescryption::keyExpansionModule(roundKey[8], _mm_aeskeygenassist_si128(roundKey[8], 0x1B));
	roundKey[10] = AESdescryption::keyExpansionModule(roundKey[9], _mm_aeskeygenassist_si128(roundKey[9], 0x36));
	//intel notice:By their definition, AESDEC and AESDECLAST should be used for decryption with the Equivalent Inverse Cipher. 
	//To this end, the encryption round keys 1-9/11/13 (for AES-128/AES-192/AES-256, respectively) need to be first passed through 
	//the InvMixColumns transformation. intel 24917.pdf(P20, P14)  
	roundKey[11] = _mm_aesimc_si128(roundKey[9]);
	roundKey[12] = _mm_aesimc_si128(roundKey[8]);
	roundKey[13] = _mm_aesimc_si128(roundKey[7]);
	roundKey[14] = _mm_aesimc_si128(roundKey[6]);
	roundKey[15] = _mm_aesimc_si128(roundKey[5]);
	roundKey[16] = _mm_aesimc_si128(roundKey[4]);
	roundKey[17] = _mm_aesimc_si128(roundKey[3]);
	roundKey[18] = _mm_aesimc_si128(roundKey[2]);
	roundKey[19] = _mm_aesimc_si128(roundKey[1]);
}
