#include <Windows.h>
#include <direct.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)			(((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL			((NTSTATUS)0xC0000001L)

int aes_dec(BYTE** plaintext, BYTE* ciphertext, int ciphertext_size, BYTE* key, int key_size, BYTE* iv) {
	NTSTATUS status = 0;

	DWORD	buffer_size = 0;
	DWORD	plaintext_length = 0;


	//(1, 3 대체) BCRYPT_AES_CBC_ALG_HANDLE
	BCRYPT_ALG_HANDLE dec_handle = BCRYPT_AES_CBC_ALG_HANDLE;

	//2. BCryptGenerateSymmetricKey
	//키 객체 생성
	BCRYPT_KEY_HANDLE key_handle = NULL;
	status = BCryptGenerateSymmetricKey(dec_handle, &key_handle, NULL, 0, key, key_size, 0);
	if (!NT_SUCCESS(status)) { printf("2번 과정 오류\n"); return 0; }

	//(4 대체) iv_length, block_length
	DWORD	iv_length = 16;
	DWORD	block_length = 16;

	//5. BCryptDecrypt: plaintext 길이 계산
	//키 핸들 / plaintext / plaintext 크기 / - / IV / IV 크기 / NULL로 설정해야 ciphertext 크기 계산 / - / 버퍼 주소 / 패딩 지정 플래그
	status = BCryptDecrypt(key_handle, ciphertext, ciphertext_size, NULL, iv, iv_length, NULL, 0, &plaintext_length, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("5번 과정 오류\n"); return 0; }

	//6. BCryptDecrypt: 복호화
	//키 핸들 / plaintext / plaintext 크기 / - / IV / IV 크기 / ciphertext 받을 버퍼 주소 / 버퍼 크기 / 복사된 값 크기 / 패딩 지정 플래그
	*plaintext = (PBYTE)calloc(plaintext_length, sizeof(BYTE));
	if (*plaintext == NULL) return 0;
	status = BCryptDecrypt(key_handle, ciphertext, ciphertext_size, NULL, iv, iv_length, *plaintext, plaintext_length, &buffer_size, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) { printf("6번 과정 오류\n"); return 0; }

	/*
	//복호문 출력
	printf("<Decrypted>\n");
	printf("%s", plaintext);
	*/

	//7. BCryptDestroyKey
	//키 폐기
	BCryptDestroyKey(key_handle);

	//8. BCryptCloseAlgorithmProvider
	//알고리즘 핸들 닫기
	BCryptCloseAlgorithmProvider(dec_handle, 0);

	return buffer_size;
}


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0) 
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define RSA_PrivateKey_BLOB_Size 1051

typedef struct _PrivateKey_BLOB {
	ULONG Magic;                // Magic number of RSAKEY 
	ULONG BitLength;            // The size(bit) of the modulus N  
	ULONG cbPublicExp;          // The size(byte) of the Public exponent e
	ULONG cbModulus;            // The size(byte) of the modulus N 
	ULONG cbPrime1;             // The size(byte) of the p 
	ULONG cbPrime2;             // The size(byte) of the q 
	BYTE PublicExponent[3];     // Array of Public Exponent e; e = 65537 = 0x01, 0x00, 0x01
	BYTE Modulus[512];          // Array of Modulus n; In RSA-4096, n = 4096-bit = 512-byte
	BYTE p[256];                // Array of Prime p
	BYTE q[256];                // Array of Prime q
} RSA_PrivateKey_BLOB;

int rsa_dec(BYTE** plaintext, BYTE* ciphertext, int ciphertext_size, RSA_PrivateKey_BLOB* private_key) {
	NTSTATUS status = 0;

	DWORD	plaintext_length = 0;
	DWORD	buffer_size = 0;

	//0. 키 핸들 생성(블롭은 복호화된 것을 사용)
	BCRYPT_KEY_HANDLE pri_handle = NULL;
	
	//1. BCRYPT_RSA_ALG_HANDLE
	BCRYPT_ALG_HANDLE dec_handle = BCRYPT_RSA_ALG_HANDLE;

	//2. BCryptImportKeyPair
	//알고리즘 핸들 / - / 키 블롭 타입 / 키 핸들 / 키 블롭 / 키 블롭 크기 / 플래그
	status = BCryptImportKeyPair(dec_handle, NULL, BCRYPT_RSAPRIVATE_BLOB, &pri_handle, (PBYTE)private_key, RSA_PrivateKey_BLOB_Size, BCRYPT_NO_KEY_VALIDATION);
	if (!NT_SUCCESS(status)) { printf("2번 오류\n"); return 0; }

	//3. BCryptDecrypt - plaintext 길이 계산
	//키 핸들 / plaintext / plaintext 크기 / 패딩 포인터 / IV 포인터 / IV 크기 / ciphertext 버퍼 / 버퍼 크기 / 복사된 값 크기 / 패딩 플래그
	status = BCryptEncrypt(pri_handle, ciphertext, ciphertext_size, NULL, NULL, 0, NULL, 0, &plaintext_length, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status)) { printf("3번 오류\n"); return 0; }

	//4. BCryptEncrypt - 복호화
	//키 핸들 / plaintext / plaintext 크기 / 패딩 포인터 / IV 포인터 / IV 크기 / ciphertext 버퍼 / 버퍼 크기 / 복사된 값 크기 / 패딩 플래그
	*plaintext = (PBYTE)calloc(plaintext_length, sizeof(BYTE));
	if (*plaintext == NULL) return 0;
	status = BCryptDecrypt(pri_handle, ciphertext, ciphertext_size, NULL, NULL, 0, *plaintext, plaintext_length, &buffer_size, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(status)) { printf("4번 오류\n"); return 0; }

	plaintext_length = buffer_size;
	/*
	//5. 암호문 출력
	printf("<Decrypted>\n");
	printf("%s\n", plaintext);
	*/

	//6. 키 폐기(키 블롭 메모리 해제는 따로 진행)
	BCryptDestroyKey(pri_handle);

	//7. 알고리즘 닫기
	BCryptCloseAlgorithmProvider(dec_handle, 0);
	return plaintext_length;
}

#define MAX_PATH 1000
#define MAX_COUNT 100000
#define CRT_SECURE_NO_WARNINGS

#pragma warning(disable:4996)

void file_search_and_encryption(char* directory, RSA_PrivateKey_BLOB* private_key, int* filecount) {
	WIN32_FIND_DATA finddata;
	HANDLE hfind;

	char path[MAX_PATH];
	sprintf(path, "%s\\*", directory);

	hfind = FindFirstFileA(path, &finddata);
	if (hfind == INVALID_HANDLE_VALUE) {
		printf("Error: %d\n", GetLastError());
		return;
	}

	do {
		//.cry 파일이 아니면 continue
		if (strcmp(finddata.cFileName + strlen(finddata.cFileName) - 4, ".cry")) continue;

		char input_name[MAX_PATH];
		sprintf(input_name, "%s\\%s", directory, finddata.cFileName);

		//디렉터리이면 continue(난 DFS를 사용했기에 여기서 재귀호출을 했었음)
		if (finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

		else {
			(*filecount)++;
			//파일 열기
			FILE* input = fopen(input_name, "rb");

			if (!input) { printf("파일 열기 오류"); return; }
			else printf("%dth:\t%s 복호화...", *filecount, input_name);
			
			//파일 크기 저장
			fseek(input, 0, SEEK_END);
			int full_size = ftell(input);
			fseek(input, 0, SEEK_SET);

			//ct, enc_key_iv 할당, 내용 저장
			int ct_size = full_size - 512;
			BYTE* ct = (PBYTE)calloc(ct_size, sizeof(BYTE));
			BYTE* enc_key_iv = (PBYTE)calloc(512, sizeof(BYTE));
			fread(ct, 1, ct_size, input);
			fread(enc_key_iv, 1, 512, input);
			fclose(input);

			//암호화된 (key||iv) 복호화
			BYTE* key_iv = NULL;
			BYTE* key = (PBYTE)calloc(32, sizeof(BYTE));
			BYTE* iv = (PBYTE)calloc(16, sizeof(BYTE));
			
			rsa_dec(&key_iv, enc_key_iv, 512, private_key);
			memcpy(key, key_iv, 32);
			memcpy(iv, key_iv + 32, 16);
			free(key_iv);

			//pt 할당, AES-256-CBC 복호화
			BYTE* pt = NULL;
			int pt_size = aes_dec(&pt, ct, ct_size, key, 32, iv);

			//파일 헤더 시그니처를 통한 확장자 복구
			char output_name[MAX_PATH];
			int output_name_len = strlen(input_name) - 4;
			memcpy(output_name, input_name, output_name_len);

			char extension[10][10] = { ".hwp", ".xls", ".pdf", ".pptx", ".docx",
				".zip", ".png", ".jpg", ".txt" };
			int header_len[8] = { 8, 8, 4, 8, 8, 3, 8, 3 };
			BYTE header[8][10] = {
				{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
				{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
				{0x25, 0x50, 0x44, 0x46},
				{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00},
				{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00},
				{0x50, 0x4B, 0x03},
				{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
				{0xFF, 0xD8, 0xFF},
			};
			int flag = 0;
			for (int i = 0;i < 8;i++) {
				if (!memcmp(pt, header[i], header_len[i])) {
					flag = 1;
					memcpy(output_name + output_name_len, extension[i], 4);
					output_name_len += 4;
				}
			}

			if (flag == 0) {
				memcpy(output_name + output_name_len, ".txt", 4);
				output_name_len += 4;
			}
			output_name[output_name_len] = 0;

			//복호화 파일 저장
			FILE* output = fopen(output_name, "wb");
			fwrite(pt, 1, pt_size, output);
			fclose(output);

			//pt, ct 해제
			free(pt);
			free(ct);
			free(key);
			free(iv);

			printf("완료!\n");
		}
	} while (FindNextFileA(hfind, &finddata) && (*filecount < MAX_COUNT));

	FindClose(hfind);
}

int main()
{
	//개인키 복구하기
	WIN32_FIND_DATA findkey;
	HANDLE hfind;

	char private_key_path[MAX_PATH] = "C:\\Users\\user\\Desktop\\Study\\code\\24_winter_FaS\\ransomware\\keystore.txt";
	FILE* keynote = fopen(private_key_path, "rb");

	//keynote 파일은 (암호화된 개인키 블롭 1056byte + 키 32byte + IV 16byte) * 2 + \n = 2209글자로 고정이므로 크기 체크하지 않음
	//enc_pri_blob, key4pri, iv4pri 할당, 내용 저장
	BYTE* enc_pri_blob = (PBYTE)calloc(1056, sizeof(BYTE));
	BYTE* key4pri = (PBYTE)calloc(32, sizeof(BYTE));
	BYTE* iv4pri = (PBYTE)calloc(16, sizeof(BYTE));

	for (int i = 0;i < 1056;i++) fscanf(keynote, "%02hhX", &enc_pri_blob[i]);
	for (int i = 0;i < 32;i++) fscanf(keynote, "%02hhX", &key4pri[i]);
	for (int i = 0;i < 16;i++) fscanf(keynote, "%02hhX", &iv4pri[i]);
	fclose(keynote);

	//개인키 블롭 복호화
	BYTE* dec_pri_blob = NULL;
	int pri_size = aes_dec(&dec_pri_blob, enc_pri_blob, 1056, key4pri, 32, iv4pri);

	RSA_PrivateKey_BLOB* private_key = (RSA_PrivateKey_BLOB * )calloc(pri_size, sizeof(BYTE));
	memcpy(private_key, dec_pri_blob, pri_size);

	free(dec_pri_blob);
	free(enc_pri_blob);
	free(key4pri);
	free(iv4pri);

	//파일 탐색 및 복호화
	int filecount = 0;
	char base_path[MAX_PATH] = "C:\\Users\\user\\Desktop\\Study\\code\\24_winter_FaS\\ransomware";
	
	file_search_and_encryption(base_path, private_key, &filecount);
	free(private_key);
	printf("--------------\n\n총 복호화된 파일 수 : %d\n", filecount);
	printf("복호화 완료!");

	return 0;
}
