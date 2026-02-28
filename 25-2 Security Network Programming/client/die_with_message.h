#ifndef DIE_WITH_MESSAGE_H
#define DIE_WITH_MESSAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>

// [치명적 오류] 메시지 출력 후 프로그램 종료 (Main, Client용)
void DieWithUserMessage(const char *msg, const char *detail);
void DieWithSystemMessage(const char *msg);
void DieWithOpenSSLError(const char *msg);

// [비치명적 오류] 메시지 출력 후 복귀 (Worker Thread용)
void PrintUserMessage(const char *msg, const char *detail);
void PrintSystemError(const char *msg);
void PrintOpenSSLError(const char *msg);

#endif