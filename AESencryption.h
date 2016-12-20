//only aes128 impelmentation
#ifndef _AES_EN_
#define _AES_EN_
#include <iostream>
#include <wmmintrin.h>
class AESencryption
{
public:
	__m128i plaintext;
	__m128i ciphertext;
	bool checkCPUsupport();
	void loadKey(const int8_t cipherKey[]);
	void loadPlaintext(const int8_t plaintext[]);
	void encryption();
	AESencryption();
	~AESencryption();
private:
	__m128i cipherKey;
	__m128i  roundKey[11];
	__m128i keyExpansionModule(const __m128i key, __m128i assistantKey);
	void keyExpansion(const __m128i cipherKey, __m128i roundKey[]);
};



#endif