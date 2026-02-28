#include <stdio.h>
#include <string.h>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#define BYTE unsigned char

int main() {
    BYTE v7[3] = { 0x10, 0x20, 0x30 };
    char v8[100];
    char Buffer[197];

    memset(v8, 0, sizeof(v8));
    memset(Buffer, 0, sizeof(Buffer));

    printf("Name: ");
    scanf("%s", v8);
    int v3 = 0;
    for (int i = 0; v3 < (int)strlen(v8); i++)
    {
        if (i >= 3)
            i = 0;
        sprintf(Buffer, "%s%02X", Buffer, v8[v3++] ^ v7[i]);
    }
    printf("\nSerial: %s", Buffer);
    return 0;
}