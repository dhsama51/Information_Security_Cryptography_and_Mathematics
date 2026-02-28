#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <openssl/ssl.h>

void load_users();
void save_users();

/* 로그인/가입 처리 (성공 시 ID 반환, 하지만 LOGIN_OK는 아직 안 보냄) */
int handle_login_register(SSL *ssl, char *out_id);

/* [추가] 중복 체크 통과 후, 실제로 카운터를 올리고 DB 저장하는 함수 */
void account_confirm_login(const char *id);

#endif