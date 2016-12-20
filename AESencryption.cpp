#include "AESencryption.h"



bool AESencryption::checkCPUsupport()
{
	int cpuInformation[4];
	__cpuid(cpuInformation, 1);
	return (cpuInformation[2] & 0x2000000);
}

void AESencryption::loadKey(const int8_t cipherKey[])
{
	this->cipherKey = _mm_loadu_si128((__m128i*) cipherKey);
	AESencryption::keyExpansion(this->cipherKey, this->roundKey);
}

void AESencryption::loadPlaintext(const int8_t plaintext[])
{
	this->plaintext = _mm_loadu_si128((__m128i*) plaintext);
}

void AESencryption::encryption()
{
	this->ciphertext = _mm_xor_si128(this->plaintext, this->roundKey[0]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[1]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[2]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[3]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[4]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[5]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[6]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[7]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[8]);
	this->ciphertext = _mm_aesenc_si128(this->ciphertext, this->roundKey[9]);
	this->ciphertext = _mm_aesenclast_si128(this->ciphertext, this->roundKey[10]);
}

AESencryption::AESencryption()
{

}

AESencryption::~AESencryption()
{
}

__m128i AESencryption::keyExpansionModule(const __m128i key, __m128i assistantKey)
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

void AESencryption::keyExpansion(const __m128i cipherKey, __m128i roundKey[])
{
	roundKey[0] = cipherKey;
	roundKey[1] = AESencryption::keyExpansionModule(roundKey[0], _mm_aeskeygenassist_si128(roundKey[0], 0x01));
	roundKey[2] = AESencryption::keyExpansionModule(roundKey[1], _mm_aeskeygenassist_si128(roundKey[1], 0x02));
	roundKey[3] = AESencryption::keyExpansionModule(roundKey[2], _mm_aeskeygenassist_si128(roundKey[2], 0x04));
	roundKey[4] = AESencryption::keyExpansionModule(roundKey[3], _mm_aeskeygenassist_si128(roundKey[3], 0x08));
	roundKey[5] = AESencryption::keyExpansionModule(roundKey[4], _mm_aeskeygenassist_si128(roundKey[4], 0x10));
	roundKey[6] = AESencryption::keyExpansionModule(roundKey[5], _mm_aeskeygenassist_si128(roundKey[5], 0x20));
	roundKey[7] = AESencryption::keyExpansionModule(roundKey[6], _mm_aeskeygenassist_si128(roundKey[6], 0x40));
	roundKey[8] = AESencryption::keyExpansionModule(roundKey[7], _mm_aeskeygenassist_si128(roundKey[7], 0x80));
	roundKey[9] = AESencryption::keyExpansionModule(roundKey[8], _mm_aeskeygenassist_si128(roundKey[8], 0x1B));
	roundKey[10] = AESencryption::keyExpansionModule(roundKey[9], _mm_aeskeygenassist_si128(roundKey[9], 0x36));
}

