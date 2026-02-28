#include "util.h"
#include "die_with_message.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define HIGHSCORE_DB "highscores.db"

int ssl_readline(SSL *ssl, char *buf, int maxlen) {
    int i = 0;
    while (i < maxlen - 1) {
        char c;
        int n = SSL_read(ssl, &c, 1);
        if (n <= 0) return -1;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return i;
}

int ssl_readline_timeout(SSL *ssl, char *buf, int maxlen, int seconds) {
    int sock = SSL_get_fd(ssl);
    if (SSL_pending(ssl) > 0) return ssl_readline(ssl, buf, maxlen);

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;

    int ret = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (ret == 0) return -2; 
    if (ret < 0) return -1;

    return ssl_readline(ssl, buf, maxlen);
}

// [추가] 정확히 len 바이트를 읽을 때까지 반복 (파일 전송용)
int ssl_read_bytes(SSL *ssl, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = SSL_read(ssl, buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

int ssl_send(SSL *ssl, const char *msg) {
    return SSL_write(ssl, msg, strlen(msg));
}

int decrypt_file_to_mem(const char *filename, char **out_buf) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) { fclose(fp); return 0; }

    unsigned char *ciphertext = malloc(fsize);
    if (!ciphertext) { fclose(fp); return -1; }
    
    if (fread(ciphertext, 1, fsize, fp) != fsize) {
        free(ciphertext); fclose(fp); return -1;
    }
    fclose(fp);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(ciphertext); return -1; }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)ENC_KEY, (unsigned char*)ENC_IV)) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext); ERR_clear_error(); return -1;
    }

    unsigned char *plaintext = malloc(fsize + AES_BLOCK_SIZE + 1);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext); return -1;
    }

    int len, plaintext_len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, fsize)) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext); free(plaintext); ERR_clear_error(); return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext); free(plaintext); ERR_clear_error(); return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    plaintext[plaintext_len] = '\0';
    *out_buf = (char*)plaintext;
    return plaintext_len;
}

int encrypt_data_to_file(const char *filename, const char *data, int data_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)ENC_KEY, (unsigned char*)ENC_IV)) {
        EVP_CIPHER_CTX_free(ctx); ERR_clear_error(); return -1;
    }

    int out_len = data_len + AES_BLOCK_SIZE;
    unsigned char *ciphertext = malloc(out_len);
    if (!ciphertext) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len, ciphertext_len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)data, data_len)) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext); ERR_clear_error(); return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext); ERR_clear_error(); return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    FILE *fp = fopen(filename, "wb");
    if (!fp) { free(ciphertext); return -1; }
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);
    free(ciphertext);
    return 0;
}

int get_high_score(const char *quiz_filename) {
    char *data = NULL;
    int len = decrypt_file_to_mem(HIGHSCORE_DB, &data);
    int high_score = 0;

    if (len >= 0) {
        char *saveptr = NULL;
        char *line = strtok_r(data, "\n", &saveptr);
        while (line) {
            char fname[128];
            int score;
            if (sscanf(line, "%127s %d", fname, &score) == 2) {
                if (strcmp(fname, quiz_filename) == 0) {
                    high_score = score;
                    break;
                }
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(data);
    }
    return high_score;
}

void update_high_score(const char *quiz_filename, int score) {
    int current_high = get_high_score(quiz_filename);
    if (score <= current_high) return; 

    char *data = NULL;
    int len = decrypt_file_to_mem(HIGHSCORE_DB, &data);
    
    int buf_size = (len > 0 ? len : 0) + 4096; 
    char *big_buf = malloc(buf_size);
    if (!big_buf) { 
        if(data) free(data); 
        PrintSystemError("malloc() failed in update_high_score");
        return; 
    }
    big_buf[0] = '\0';

    int found = 0;
    if (len >= 0) {
        char *saveptr = NULL;
        char *line = strtok_r(data, "\n", &saveptr);
        while (line) {
            char fname[128];
            int s;
            sscanf(line, "%127s %d", fname, &s);
            if (strcmp(fname, quiz_filename) == 0) {
                char temp[256];
                sprintf(temp, "%s %d\n", quiz_filename, score);
                strcat(big_buf, temp);
                found = 1;
            } else {
                strcat(big_buf, line);
                strcat(big_buf, "\n");
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(data);
    }

    if (!found) {
        char temp[256];
        sprintf(temp, "%s %d\n", quiz_filename, score);
        strcat(big_buf, temp);
    }

    encrypt_data_to_file(HIGHSCORE_DB, big_buf, strlen(big_buf));
    free(big_buf);
    printf("[Server] New High Score: %s -> %d\n", quiz_filename, score);
}