#include <Windows.h>
#include <direct.h> // pdf의 예시코드에는 없는데 난 추가해야만 _getcwd()가 작동함
#include <stdio.h>

#define MAX_PATH 4096
#define CRT_SECURE_NO_WARNINGS

#pragma warning(disable:4996)

void file_search(char filenames[][MAX_PATH], int* filecount) {

	char directory[4096]; // Current directory
	_getcwd(directory, 4096);

	WIN32_FIND_DATA finddata;
	HANDLE hfind;

	char path[MAX_PATH];

	sprintf(path, "%s\\*", directory);

	hfind = FindFirstFileA(path, &finddata);
	if (hfind == INVALID_HANDLE_VALUE) {
		printf("Error: %d\n", GetLastError());
		return;
	}

	else if (hfind != INVALID_HANDLE_VALUE) {
		do {
			strcpy(filenames[*filecount], finddata.cFileName);
			(*filecount)++;
		} while (FindNextFileA(hfind, &finddata) && (*filecount < 100));

		FindClose(hfind);
	}
}

int main() {
	char filenames[100][MAX_PATH];
	int filecount = 0;

	file_search(filenames, &filecount);

	for (int i = 0; i < filecount; i++) printf("%s\n", filenames[i]);

	return 0;
}