#ifndef UTIL_H
#define UTIL_H

#include <openssl/ssl.h>

#define ENC_KEY "01234567890123456789012345678901"
#define ENC_IV  "0123456789012345"

int ssl_readline(SSL *ssl, char *buf, int maxlen);
int ssl_readline_timeout(SSL *ssl, char *buf, int maxlen, int seconds);
// [추가] 지정된 바이트 수만큼 읽는 함수 (파일 업로드용)
int ssl_read_bytes(SSL *ssl, char *buf, int len);

int ssl_send(SSL *ssl, const char *msg);

int decrypt_file_to_mem(const char *filename, char **out_buf);
int encrypt_data_to_file(const char *filename, const char *data, int len);

int get_high_score(const char *quiz_filename);
void update_high_score(const char *quiz_filename, int score);

#endif