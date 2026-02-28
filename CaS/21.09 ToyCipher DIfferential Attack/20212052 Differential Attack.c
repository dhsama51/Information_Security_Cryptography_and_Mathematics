#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

//unsigned char make_y(unsigned char y, unsigned char yone, unsigned char ytwo)
//{
//	int i = 0;
//	for (i = 0; i < 8; i++)
//		y = yone ^ ytwo;
//
//	return y;
//}

void filewrite()
{
	FILE* f = fopen("C:\\Users\\이동훈\\Downloads\\TC32실행파일\\PlainText.txt", "w");

	srand((unsigned int)time(NULL));
	int i = 0, j = 0, a = rand(), b = rand(), c = 0;
	for (int i = 0; i < 10; i++)
	{
		a = rand();
		b = rand();
		c = (a << 16) | b;
		printf("%X\n", c);
	}
	for (i = 0; i < 2048; i++)
	{
		fprintf(f, "%X\n%X\n", c, c ^ 0x1);

		a = rand();
		b = rand();
		c = (a << 16) | b;
	}

	fclose(f);
	printf("완료");
}

void fileread(unsigned int* yone[], unsigned int* ytwo[])
{
	//FILE* f = fopen("C:\\Users\\이동훈\\Downloads\\TC32실행파일\\CipherText.txt", "r");
	//
	//int i = 0, j = 0;

	//for (i = 0; i < 2048; i++)
	//	fscanf(f, "%X%X", &yone[i], &ytwo[i]);
	////for (i = 0; i < 2048; i++)
	////	printf("%X\n%X\n\n", yone[i], ytwo[i]);
	//fclose(f);
	printf("hello");
}

unsigned char InvSbox[16] = { 0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb, 0xe, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5 };

void arrange(unsigned int yone[], unsigned int ytwo[])
{
	int i = 0;
	
	for (i = 0; i < 2048; i++)
	{
		yone[i] = (yone[i] & 0x00f00000) / 0x100000;
		ytwo[i] = (ytwo[i] & 0x00f00000) / 0x100000;
	}
}

void DifferentialAttack(unsigned int yone[], unsigned int ytwo[])
 {
	unsigned int yonebuf = { 0 };
	unsigned int ytwobuf = { 0 };
	unsigned int x = 1, y = 0;
	unsigned int key = 0;
	arrange(yone, ytwo);
	int i = 0, j = 0, k = 0, max = -1, a = 0, count[16] = { 0 };
	printf("차분 공격 시작\n");

	for (i = 0; i <= 0xf; i++)
	{
		key = i;
		for (j = 0; j < 0x800/*2048*/; j++)
		{
			yonebuf = yone[j] ^ key;
			ytwobuf = ytwo[j] ^ key;
			yonebuf = InvSbox[yonebuf];
			ytwobuf = InvSbox[ytwobuf];
	
			y = yonebuf ^ ytwobuf;
	
			if (x == y)
				count[i]++;
		}
	}
	
	printf("찾은 키\n");
	for (i = 0; i < 0xf; i++)
		if (count[i] > max)
			max = count[i];
	for (i = 0; i < 0xf; i++)
		if (count[i] >= max)
			printf("0x%x\n", i);
	printf("카운터: %d\n\n", max);
	for (i = 0; i < 16; i++)
		printf("%d\n", count[i]);
}

int main()
{
	unsigned int yone[2048] = { 0 }, ytwo[2048] = { 0 };
	filewrite();
	//fileread(yone, ytwo);
	//DifferentialAttack(yone, ytwo);
}