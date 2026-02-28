#include <stdio.h>
#include <string.h>
#pragma warning(disable : 4996)
#define BYTE unsigned char

int main() {
    BYTE key[3] = { 0x10, 0x20, 0x30 };
    char serial[100] = { 0, };
    char Name[197] = { 0, };

    printf("input Serial: ");
    scanf("%s", serial);
    
    int hex = 0;
    for (int i = 0; i < strlen(serial) / 2;i++) {
        sscanf(serial + i * 2, "%02X", &hex);
        sprintf(Name, "%s%c", Name, hex ^ key[i % 3]);
    }
    printf("Name: %s", Name);

    return 0;
}