#include <Windows.h>
#include <bcrypt.h> //Windows.h를 먼저 포함해야 컴파일 오류 미발생.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0) 
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L) //헤더파일에 이미 선언돼있으나 명시하는 것이 바람직.


BYTE rng(BYTE* random, int random_size) {
	NTSTATUS status;
	BCRYPT_ALG_HANDLE handle = NULL; //알고리즘 핸들. 알고리즘 컨텍스트를 저장, 접근, 조작하는 식별자.

	//알고리즘 핸들로 알고리즘 열고 초기화
	status = BCryptOpenAlgorithmProvider(&handle, BCRYPT_RNG_ALGORITHM, NULL, 0);

	if (!NT_SUCCESS(status)) return 0;

	//버퍼보다 더 크게 생성하면 메모리 오버플로우, 작게 생성하면 뒤는 0 초기화 유지.
	status = BCryptGenRandom(handle, random, random_size, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER);
	if (!NT_SUCCESS(status)) return 0;

	status = BCryptCloseAlgorithmProvider(handle, 0);
	
	return *random;
}

int main() {
	BYTE random[48] = { 0, };
	rng(random, sizeof(random));

	printf("<Random %d byte>\n", 48);
	for (int i = 0;i < 24;i++) printf("%02X ", random[i]);
	printf("\n");
	for (int i = 24;i < 48;i++) printf("%02X ", random[i]); //난수 출력

	BYTE key[32] = { 0, }, iv[16] = { 0, };
	
	memcpy(key, random, 32);
	memcpy(iv, random + 32, 16);

	printf("\n\n<Random key %d byte>\n", 32);
	for (int i = 0;i < 32;i++) printf("%02X ", key[i]); //key 출력
	printf("\n<Random iv %d byte>\n", 16);
	for (int i = 0;i < 16;i++) printf("%02X ", iv[i]); //iv 출력
	printf("\n");

	return 0;
}