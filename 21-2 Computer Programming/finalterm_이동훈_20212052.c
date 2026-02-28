#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

// 마스터 키
unsigned char pbUserKey[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
unsigned char sub_key[2][128] = { 0 };//첫번째 행은 sub key, 두번째 행은 whitening key

// 평문 데이터
unsigned char data[128] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ,
							0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00,
							0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00, 0x11,
							0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ,0x00, 0x11, 0x22,
							0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00, 0x11, 0x22, 0x33,
							0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ,0x00, 0x11, 0x22, 0x33, 0x44,
							0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff , 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
							0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, };

#define MASTER_KEY_LEN	16
#define PT_LEN	sizeof(data)
#define CT_LEN	(sizeof(data) + ((8 - sizeof(data) % 8) % 8))

// IV 값
unsigned char iv[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
unsigned char cipher[CT_LEN] = { 0 };
unsigned char recover[PT_LEN] = { 0 };


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
int encrypt(unsigned char* ciphertext, unsigned char* plaintext, int ptSize, unsigned char* IV, unsigned char (*roundKey)[128])
{
	int i = 0, j = 0, a = PT_LEN;
	unsigned char padded[CT_LEN] = { 0 };
	unsigned char buf[8] = { 0 };

	memcpy(padded, plaintext, PT_LEN);

	memcpy(buf, padded, 8);
	for (j = 0; j < 8; j++)
		buf[j] ^= IV[j];
	for (i = 0; i < (CT_LEN / 8) - 1; i++)
	{
		initial(ciphertext + 8 * i, buf, roundKey);
		round(ciphertext + 8 * i, roundKey);
		round32(ciphertext + 8 * i, roundKey);
		final(ciphertext + 8 * i, roundKey);

		memcpy(buf, ciphertext + 8 * i, 8);
		for (j = 0; j < 8; j++)
			buf[j] ^= padded[8 * i + j + 8];
	}
	initial(ciphertext + CT_LEN - 8, buf, roundKey);
	round(ciphertext + CT_LEN - 8, roundKey);
	round32(ciphertext + CT_LEN - 8, roundKey);
	final(ciphertext + CT_LEN - 8, roundKey);

	return ptSize;
}

// 복호화 수행 함수 선언
int decrypt(unsigned char* recovered, unsigned char* ciphertext, int ctSize, unsigned char* IV, unsigned char* roundKey)
{
	int i = 0, j = 0;
	unsigned char padded[CT_LEN] = { 0 };
	unsigned char buf[8] = { 0 };

	memcpy(buf, ciphertext, 8);
	invinitial(padded, buf, roundKey);
	invround(padded, roundKey);
	invround32(padded, roundKey);
	invfinal(padded, roundKey);

	for (j = 0; j < 8; j++)
		padded[j] ^= IV[j];
	for (i = 1; i < CT_LEN / 8; i++)
	{
		memcpy(buf, ciphertext + 8 * i, 8);
		invinitial(padded + 8 * i, buf, roundKey);
		invround(padded + 8 * i, roundKey);
		invround32(padded + 8 * i, roundKey);
		invfinal(padded + 8 * i, roundKey);

		for (j = 0; j < 8; j++)
			padded[j + 8 * i] ^= ciphertext[j - 8 + 8 * i];
	}
	memcpy(recovered, padded, PT_LEN);

	return ctSize;
}

void print_recv(unsigned char* recv, char* what, int size)
{
	printf("[%s]\n", what);
	for (int i = 0; i < size / 8; i++)
		printf("%02X %02X %02X %02X %02X %02X %02X %02X\n", recv[8 * i + 0], recv[8 * i + 1], recv[8 * i + 2], recv[8 * i + 3], recv[8 * i + 4], recv[8 * i + 5], recv[8 * i + 6], recv[8 * i + 7]);
	printf("\n");
}

void HW1_cbc_test()
{
	key_schedule(sub_key, pbUserKey, MASTER_KEY_LEN);
	print_recv(data, "plaintext", PT_LEN);
	encrypt(cipher, data, PT_LEN, iv, sub_key);
	print_recv(cipher, "ciphertext", CT_LEN);
	decrypt(recover, cipher, CT_LEN, iv, sub_key);
	print_recv(recover, "recovered", PT_LEN);
	printf("\n\n");
}

void str_to_hex(unsigned char* a, int size)
{
	for (int i = 0; i < size; i++)
		if (a[i] <= '9' && a[i] >= '0')
			a[i] = a[i] - '0';
		else if (a[i] <= 'F' && a[i] >= 'A')
			a[i] = a[i] - 'A' + 0xa;
}

void setting(FILE* f, unsigned char* A, unsigned char* factor, int size)
{
	int i = 0;

	fgets(A, size * 2 + 1, f);
	str_to_hex(A, size * 2);
	for (i = 0; i < size; i++)
		factor[i] = A[2 * i] * 16 + A[2 * i + 1];
}

void change_data(unsigned char* SK, unsigned char* IV, unsigned char* PT, int size)
{
	int i = 0;

	for (i = 0; i < 8; i++)
		iv[i] = IV[i];
	for (i = 0; i < size; i++)
		data[i] = PT[i];
	for (i = size; i < 40; i++)
		data[i] = 0;
}

void HW2_cbc_test_with_file()
{
	unsigned char A[100] = { 0 };
	unsigned char K[16] = { 0 }, SK[2][128] = { 0 }, IV[8] = { 0 }, PT[40] = { 0 }, CT[40] = { 0 };
	int i = 0, j = 0;

	FILE* f = fopen("testvector.txt", "r");
	FILE* g = fopen("result.txt", "w");

	for (j = 0; j < 5; j++)
	{
		if (j == 0)
			fseek(f, 6, SEEK_CUR);
		else
			fseek(f, 18, SEEK_CUR);
		setting(f, A, K, 16);
		
		fseek(f, 7, SEEK_CUR);
		setting(f, A, IV, 8);
		
		fseek(f, 7, SEEK_CUR);
		setting(f, A, PT, 8 * j + 8);

		key_schedule(SK, K, MASTER_KEY_LEN);
		change_data(SK, IV, PT, 8 * j + 8);
		encrypt(cipher, data, PT_LEN, iv, SK);
		memcpy(CT, cipher, 8 * j + 8);

		fprintf(g, "KEY = ");
		for (i = 0; i < 16; i++)
			fprintf(g, "%02X", K[i]);
		fprintf(g, "\nIV = ");
		for (i = 0; i < 8; i++)
			fprintf(g, "%02X", IV[i]);
		fprintf(g, "\nPT = ");
		for (i = 0; i < 8 * j + 8; i++)
			fprintf(g, "%02X", PT[i]);
		fprintf(g, "\nCT = ");
		for (i = 0; i < 8 * j + 8; i++)
			fprintf(g, "%02X", CT[i]);
		if (j != 4)
			fprintf(g, "\n\n");
	}

	fclose(f);
	fclose(g);
}

int main()
{
	printf("20212052 이동훈\n");
	HW1_cbc_test();
	HW2_cbc_test_with_file();
	return 0;
}