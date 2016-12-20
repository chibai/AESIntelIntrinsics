#include<iostream>
#include"AESencryption.h"
#include"AESdescryption.h"
using namespace std;

int main()
{
	int i;
	AESencryption aesEn;
	AESdescryption aesDe;
	if (!aesEn.checkCPUsupport())
	{
		cerr << "cpu do not support Intel AES instruction" << endl;
		exit(-1);
	}
	//
	int8_t cipherKey[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	int8_t plaintext[] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	int8_t descriptiontext[16];
	aesEn.loadKey(cipherKey);
	aesEn.loadPlaintext(plaintext);
	aesEn.encryption();
	//transfer the data
	aesDe.loadKey(cipherKey);
	aesDe.loadCiphertext((int8_t*)&aesEn.ciphertext);
	aesDe.descryption();
	//output the result
	_mm_storeu_si128((__m128i*)descriptiontext, aesDe.plaintext);
	if (0 == memcmp(plaintext, descriptiontext, sizeof(plaintext)))
	{
		cout << "success" << endl;
	}
	return 0;
}