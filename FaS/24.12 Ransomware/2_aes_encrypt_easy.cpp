#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

void aes_enc(BYTE* plaintext, int plaintext_size, BYTE* ciphertext, BYTE* key, int key_size, BYTE* iv) {
	NTSTATUS status = 0;

	DWORD	buffer_size = 0;
	DWORD	ciphertext_length = 0;


	//(1, 3 대체) BCRYPT_AES_CBC_ALG_HANDLE
	BCRYPT_ALG_HANDLE enc_handle = BCRYPT_AES_CBC_ALG_HANDLE;

	//2. BCryptGenerateSymmetricKey
	//키 객체 생성
	BCRYPT_KEY_HANDLE key_handle = NULL;
	status = BCryptGenerateSymmetricKey(enc_handle, &key_handle, NULL, 0, key, key_size, 0);
	if (!NT_SUCCESS(status)) { printf("2번 과정 오류\n"); return; }

	//(4 대체) iv_length, block_length
	DWORD	iv_length = 16;
	DWORD	block_length = 16;

	//5. BCryptEncrypt: ciphertext 길이 계산
	//키 핸들 / plaintext / plaintext 크기 / - / IV / IV 크기 / NULL로 설정해야 ciphertext 크기 계산 / - / 버퍼 주소 / 패딩 지정 플래그
	status = BCryptEncrypt(key_handle, plaintext, plaintext_size, NULL, iv, iv_length, NULL, 0, &ciphertext_length, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("5번 과정 오류\n"); return; }

	//6. BCryptEncrypt: 암호화
	//키 핸들 / plaintext / plaintext 크기 / - / IV / IV 크기 / ciphertext 받을 버퍼 주소 / 버퍼 크기 / 복사된 값 크기 / 패딩 지정 플래그
	ciphertext = (PBYTE)calloc(ciphertext_length, sizeof(BYTE));
	if (ciphertext == NULL) return;
	status = BCryptEncrypt(key_handle, plaintext, plaintext_size, NULL, iv, iv_length, ciphertext, ciphertext_length, &buffer_size, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("6번 과정 오류\n"); return; }

	//암호문 출력
	printf("<Encrypted>\n");
	for (int i = 0; i < ciphertext_length; i++) printf("%02X ", ciphertext[i]);

	//7. BCryptDestroyKey
	//키 폐기
	BCryptDestroyKey(key_handle);

	//8. BCryptCloseAlgorithmProvider
	//알고리즘 핸들 닫기
	BCryptCloseAlgorithmProvider(enc_handle, 0);

	return;
}

int main()
{
	BYTE key[16] = { 0x20, 0x19, 0x22, 0x43, 0x20, 0x25, 0x01, 0x14,
				   0xFF, 0xFF, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
	BYTE iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE plaintext[] = "FaS 2025 Nice Happy Good~";
	BYTE* ciphertext = NULL;

	aes_enc(plaintext, sizeof(plaintext), ciphertext, key, sizeof(key), iv); //enc() 안에서 sizeof() 수행하면 값이 달라져서 매개변수로 전달
	free(ciphertext);
	return 0;
}
