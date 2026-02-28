#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>


#define MASTER_KEY_LEN	16
#define PT_LEN	8
#define CT_LEN	8

unsigned char delta[128] = {
		0x5A,0x6D,0x36,0x1B,0x0D,0x06,0x03,0x41,
		0x60,0x30,0x18,0x4C,0x66,0x33,0x59,0x2C,
		0x56,0x2B,0x15,0x4A,0x65,0x72,0x39,0x1C,
		0x4E,0x67,0x73,0x79,0x3C,0x5E,0x6F,0x37,
		0x5B,0x2D,0x16,0x0B,0x05,0x42,0x21,0x50,
		0x28,0x54,0x2A,0x55,0x6A,0x75,0x7A,0x7D,
		0x3E,0x5F,0x2F,0x17,0x4B,0x25,0x52,0x29,
		0x14,0x0A,0x45,0x62,0x31,0x58,0x6C,0x76,
		0x3B,0x1D,0x0E,0x47,0x63,0x71,0x78,0x7C,
		0x7E,0x7F,0x3F,0x1F,0x0F,0x07,0x43,0x61,
		0x70,0x38,0x5C,0x6E,0x77,0x7B,0x3D,0x1E,
		0x4F,0x27,0x53,0x69,0x34,0x1A,0x4D,0x26,
		0x13,0x49,0x24,0x12,0x09,0x04,0x02,0x01,
		0x40,0x20,0x10,0x08,0x44,0x22,0x11,0x48,
		0x64,0x32,0x19,0x0C,0x46,0x23,0x51,0x68,
		0x74,0x3A,0x5D,0x2E,0x57,0x6B,0x35,0x5A };
	
// 키 스케쥴 수행 함수 선언
void key_schedule(unsigned char (*roundKey)[128], unsigned char* masterKey, int masterKeyLen)
{
	int i = 0, j = 0;

	for (i = 0; i < 8; i++)
	{
		for (j = 0; j < 8; j++)
			roundKey[0][16 * i + j] = (masterKey[(j - i + 8) % 8] + delta[16 * i + j]) % 256;
		for (j = 0; j < 8; j++)
			roundKey[0][16 * i + j + 8] = (masterKey[(j - i + 8) % 8 + 8] + delta[16 * i + j + 8]) % 256;
	}
	
	for (i = 0; i < 4; i++)
		roundKey[1][i] = masterKey[i + 12];
	for (i = 4; i < 8; i++)
		roundKey[1][i] = masterKey[i - 4];
}

void initial(unsigned char* cipher, unsigned char* plain, unsigned char (*roundKey)[128])
{
	cipher[1] = plain[1];
	cipher[3] = plain[3];
	cipher[5] = plain[5];
	cipher[7] = plain[7];
	cipher[0] = (plain[0] + roundKey[1][0]) % 256;
	cipher[2] = plain[2] ^ roundKey[1][1];
	cipher[4] = (plain[4] + roundKey[1][2]) % 256;
	cipher[6] = plain[6] ^ roundKey[1][3];
}

unsigned char Fzero(unsigned char* a)
{
	return ((*a << 1) | (*a >> 7)) ^ ((*a << 2) | (*a >> 6)) ^ ((*a << 7) | (*a >> 1));
}

unsigned char Fone(unsigned char* a)
{
	return ((*a << 3) | (*a >> 5)) ^ ((*a << 4) | (*a >> 4)) ^ ((*a << 6) | (*a >> 2));
}

void round(unsigned char* cipher, unsigned char (*roundKey)[128])
{
	int i = 0, j = 0;
	for (i = 1; i < 32; i++)
	{
		unsigned char temp[8] = { 0 };
		temp[1] = cipher[0];
		temp[3] = cipher[2];
		temp[5] = cipher[4];
		temp[7] = cipher[6];
		temp[0] = cipher[7] ^ ((Fzero(&cipher[6]) + roundKey[0][4 * i - 1]) % 256);
		temp[2] = (cipher[1] + (Fone(&cipher[0]) ^ roundKey[0][4 * i - 4])) % 256;
		temp[4] = cipher[3] ^ ((Fzero(&cipher[2]) + roundKey[0][4 * i - 3]) % 256);
		temp[6] = (cipher[5] + (Fone(&cipher[4]) ^ roundKey[0][4 * i - 2])) % 256;
		
		for (j = 0; j < 8; j++)
			cipher[j] = temp[j];
	}
}

void round32(unsigned char* cipher, unsigned char (*roundKey)[128])
{
	int i = 0;
	unsigned char temp[8] = { 0 };
	temp[0] = cipher[0];
	temp[2] = cipher[2];
	temp[4] = cipher[4];
	temp[6] = cipher[6];
	temp[1] = (cipher[1] + (Fone(&cipher[0]) ^ roundKey[0][124])) % 256;
	temp[3] = cipher[3] ^ ((Fzero(&cipher[2]) + roundKey[0][125]) % 256);
	temp[5] = (cipher[5] + (Fone(&cipher[4]) ^ roundKey[0][126])) % 256;
	temp[7] = cipher[7] ^ ((Fzero(&cipher[6]) + roundKey[0][127]) % 256);

	for (i = 0; i < 8; i++)
		cipher[i] = temp[i];
}

void final(unsigned char* cipher, unsigned char (*roundKey)[128])
{
	cipher[1] = cipher[1];
	cipher[3] = cipher[3];
	cipher[5] = cipher[5];
	cipher[7] = cipher[7];
	cipher[0] = (cipher[0] + roundKey[1][4]) % 256;
	cipher[2] = cipher[2] ^ roundKey[1][5];
	cipher[4] = (cipher[4] + roundKey[1][6]) % 256;
	cipher[6] = cipher[6] ^ roundKey[1][7];
}

void invinitial(unsigned char* recover, unsigned char* cipher, unsigned char(*roundKey)[128])
{
	recover[1] = cipher[1];
	recover[3] = cipher[3];
	recover[5] = cipher[5];
	recover[7] = cipher[7];
	recover[0] = (cipher[0] - roundKey[1][4] + 256) % 256;
	recover[2] = cipher[2] ^ roundKey[1][5];
	recover[4] = (cipher[4] - roundKey[1][6] + 256) % 256;
	recover[6] = cipher[6] ^ roundKey[1][7];
}

void invround(unsigned char* recover, unsigned char(*roundKey)[128])
{
	int i = 0, j = 0;
	for (i = 1; i < 32; i++)
	{
		unsigned char temp[8] = { 0 };
		temp[1] = recover[2];
		temp[3] = recover[4];
		temp[5] = recover[6];
		temp[7] = recover[0];
		temp[0] = (recover[1] - (Fone(&recover[0]) ^ roundKey[0][127 - (4 * i - 1)]) + 256) % 256;
		temp[2] = recover[3] ^ ((Fzero(&recover[2]) + roundKey[0][127 - (4 * i - 2)]) % 256);
		temp[4] = (recover[5] - (Fone(&recover[4]) ^ roundKey[0][127 - (4 * i - 3)]) + 256) % 256;
		temp[6] = recover[7] ^ ((Fzero(&recover[6]) + roundKey[0][127 - (4 * i - 4)]) % 256);
		
		for (j = 0; j < 8; j++)
			recover[j] = temp[j];
	}
}

void invround32(unsigned char* recover, unsigned char(*roundKey)[128])
{
	int i = 0;
	unsigned char temp[8] = { 0 };
	temp[0] = recover[0];
	temp[2] = recover[2];
	temp[4] = recover[4];
	temp[6] = recover[6];
	temp[1] = (recover[1] - (Fone(&recover[0]) ^ roundKey[0][0]) + 256) % 256;
	temp[3] = recover[3] ^ ((Fzero(&recover[2]) + roundKey[0][1]) % 256);
	temp[5] = (recover[5] - (Fone(&recover[4]) ^ roundKey[0][2]) + 256) % 256;
	temp[7] = recover[7] ^ ((Fzero(&recover[6]) + roundKey[0][3]) % 256);

	for (i = 0; i < 8; i++)
		recover[i] = temp[i];
}

void invfinal(unsigned char* recover, unsigned char(*roundKey)[128])
{
	recover[1] = recover[1];
	recover[3] = recover[3];
	recover[5] = recover[5];
	recover[7] = recover[7];
	recover[0] = (recover[0] - roundKey[1][0] + 256) % 256;
	recover[2] = recover[2] ^ roundKey[1][1];
	recover[4] = (recover[4] - roundKey[1][2] + 256) % 256;
	recover[6] = recover[6] ^ roundKey[1][3];
}

// 암호화 수행 함수 선언
int encrypt(unsigned char* ciphertext, unsigned char* plaintext, int ptSize, unsigned char (*roundKey)[128])
{
	int i = 0;

	printf("Plaintext :");
	for (i = 0; i < 8; i++)
		printf(" %02X", plaintext[i]);
	printf("\nEncryption...\n");

	initial(ciphertext, plaintext, roundKey);
	round(ciphertext, roundKey);
	round32(ciphertext, roundKey);
	final(ciphertext, roundKey);

	printf("Ciphertext :");
	for (i = 0; i < 8; i++)
		printf(" %02X", ciphertext[i]);
	printf("\n\n");

	return ptSize;
}

// 복호화 수행 함수 선언
int decrypt(unsigned char* recovered, unsigned char* ciphertext, int ctSize, unsigned char* roundKey)
{
	int i = 0;

	printf("Decryption...\n");

	invinitial(recovered, ciphertext, roundKey);
	invround(recovered, roundKey);
	invround32(recovered, roundKey);
	invfinal(recovered, roundKey);

	printf("Plaintext :");
	for (i = 0; i < 8; i++)
		printf(" %02X", recovered[i]);
	printf("\n\n");

	return ctSize;
}

void test_encryption()
{
	unsigned char master_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char sub_key[2][128] = { 0 };//첫번째 행은 sub key, 두번째 행은 whitening key
	
	unsigned char test_vector1[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned char test_vector2[8] = { 0xD7, 0x6D, 0x0D, 0x18, 0x32, 0x7E, 0xC5, 0x62 };
	unsigned char test_vector3[8] = { 0x7D, 0xD6, 0xD0, 0x81, 0x23, 0xE7, 0x5C, 0x26 };
	unsigned char test_vector4[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	
	unsigned char cipher1[8] = { 0 };
	unsigned char cipher2[8] = { 0 };
	unsigned char cipher3[8] = { 0 };
	unsigned char cipher4[8] = { 0 };
	
	unsigned char recover1[8] = { 0 };
	unsigned char recover2[8] = { 0 };
	unsigned char recover3[8] = { 0 };
	unsigned char recover4[8] = { 0 };

	printf("Master Key :");
	for (int i = 0; i < MASTER_KEY_LEN; i++)
		printf(" %02X", master_key[i]);
	printf("\n\n");

	key_schedule(sub_key, master_key, MASTER_KEY_LEN);
	printf("[1-th Test]\n\n");
	encrypt(cipher1, test_vector1, PT_LEN, sub_key);
	decrypt(recover1, cipher1, CT_LEN, sub_key);
	
	printf("[2-th Test]\n\n");
	encrypt(cipher2, test_vector2, PT_LEN, sub_key);
	decrypt(recover2, cipher2, CT_LEN, sub_key);
	
	printf("[3-th Test]\n\n");
	encrypt(cipher3, test_vector3, PT_LEN, sub_key);
	decrypt(recover3, cipher3, CT_LEN, sub_key);

	printf("[4-th Test]\n\n");
	encrypt(cipher4, test_vector4, PT_LEN, sub_key);
	decrypt(recover4, cipher4, CT_LEN, sub_key);
}

int main()
{
	printf("20212052 이동훈\n");
	test_encryption();

	return 0;
}