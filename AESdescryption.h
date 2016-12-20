#ifndef _AES_DE_
#define _AES_DE_
#include <iostream>
#include <wmmintrin.h>
class AESdescryption
{
public:
	__m128i ciphertext;
	__m128i plaintext;
	bool checkCPUsupport();
	void loadKey(const int8_t cipherKey[]);
	void loadCiphertext(const int8_t ciphertext[]);
	void descryption();
	AESdescryption();
	~AESdescryption();
private:
	__m128i cipherKey;
	__m128i  roundKey[20];
	__m128i keyExpansionModule(const __m128i key, __m128i assistantKey);
	void keyExpansion(const __m128i cipherKey, __m128i roundKey[]);
};

#endif