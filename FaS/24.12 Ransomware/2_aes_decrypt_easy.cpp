#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

void aes_dec(BYTE* plaintext,BYTE* ciphertext, int ciphertext_size, BYTE* key, int key_size, BYTE* iv) {
	NTSTATUS status = 0;

	DWORD	buffer_size = 0;
	DWORD	plaintext_length = 0;


	//(1, 3 대체) BCRYPT_AES_CBC_ALG_HANDLE
	BCRYPT_ALG_HANDLE dec_handle = BCRYPT_AES_CBC_ALG_HANDLE;

	//2. BCryptGenerateSymmetricKey
	//키 객체 생성
	BCRYPT_KEY_HANDLE key_handle = NULL;
	status = BCryptGenerateSymmetricKey(dec_handle, &key_handle, NULL, 0, key, key_size, 0);
	if (!NT_SUCCESS(status)) { printf("2번 과정 오류\n"); return; }

	//(4 대체) iv_length, block_length
	DWORD	iv_length = 16;
	DWORD	block_length = 16;

	//5. BCryptDecrypt: plaintext 길이 계산
	//키 핸들 / plaintext / plaintext 크기 / - / IV / IV 크기 / NULL로 설정해야 ciphertext 크기 계산 / - / 버퍼 주소 / 패딩 지정 플래그
	status = BCryptDecrypt(key_handle, ciphertext, ciphertext_size, NULL, iv, iv_length, NULL, 0, &plaintext_length, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("5번 과정 오류\n"); return; }

	//6. BCryptDecrypt: 복호화
	//키 핸들 / plaintext / plaintext 크기 / - / IV / IV 크기 / ciphertext 받을 버퍼 주소 / 버퍼 크기 / 복사된 값 크기 / 패딩 지정 플래그
	plaintext = (PBYTE)calloc(plaintext_length, sizeof(BYTE));
	if (plaintext == NULL) return;
	status = BCryptDecrypt(key_handle, ciphertext, ciphertext_size, NULL, iv, iv_length, plaintext, plaintext_length, &buffer_size, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("6번 과정 오류\n"); return; }

	//복호문 출력
	printf("<Decrypted>\n");
	printf("%s", plaintext);

	//7. BCryptDestroyKey
	//키 폐기
	BCryptDestroyKey(key_handle);

	//8. BCryptCloseAlgorithmProvider
	//알고리즘 핸들 닫기
	BCryptCloseAlgorithmProvider(dec_handle, 0);

	return;
}

int main()
{
	BYTE key[16] = { 0x20, 0x19, 0x22, 0x43, 0x20, 0x25, 0x01, 0x14,
				   0xFF, 0xFF, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
	BYTE iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE* plaintext = NULL;
	BYTE ciphertext[] = { 0xE7, 0x1B, 0xA0, 0x08, 0x97, 0x36, 0x17, 0xD7,
				   0xE7, 0xDB, 0x34, 0xDC, 0x2A, 0xEB, 0x1E, 0x0E,
				   0x53, 0x4B, 0x56, 0x75, 0xB6, 0x83, 0xC2, 0xC6,
				   0xF7, 0xDA, 0xFB, 0x2E, 0x4F, 0x32, 0x38, 0xD9, };

	aes_dec(plaintext, ciphertext, sizeof(ciphertext), key, sizeof(key), iv); //dec() 안에서 sizeof() 수행하면 값이 달라져서 매개변수로 전달
	free(plaintext);
	return 0;
}
