#include "die_with_message.h"

// 1. 사용자 정의 오류 (치명적)
void DieWithUserMessage(const char *msg, const char *detail) {
    fputs(msg, stderr);
    fputs(": ", stderr);
    fputs(detail, stderr);
    fputc('\n', stderr);
    exit(1);
}

// 2. 시스템 오류 (perror 대체, 치명적)
void DieWithSystemMessage(const char *msg) {
    perror(msg);
    exit(1);
}

// 3. OpenSSL 오류 (치명적)
void DieWithOpenSSLError(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

// 4. 사용자 정의 오류 (로그만 남김)
void PrintUserMessage(const char *msg, const char *detail) {
    fprintf(stderr, "[Log] %s: %s\n", msg, detail);
}

// 5. 시스템 오류 (로그만 남김)
void PrintSystemError(const char *msg) {
    perror(msg); // 종료하지 않음
}

// 6. OpenSSL 오류 (로그만 남김)
void PrintOpenSSLError(const char *msg) {
    fprintf(stderr, "[SSL Log] %s\n", msg);
    ERR_print_errors_fp(stderr);
}