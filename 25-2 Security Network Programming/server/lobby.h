#ifndef LOBBY_H
#define LOBBY_H

#include <openssl/ssl.h>

#define MAX_CLIENTS 10

typedef struct {
    int used;
    SSL *ssl;
    char id[64];
    int score; 
} LobbyClient;

void lobby_init();
int lobby_add(SSL *ssl, const char *id);
void lobby_remove(SSL *ssl);
int lobby_is_admin(SSL *ssl);
void lobby_broadcast(const char *msg);

void lobby_handle_start_command(SSL *ssl, const char *msg);
void lobby_wait_for_start(SSL *ssl);
const char* lobby_get_quiz_file();

// [수정] difficulty 인자 추가
void lobby_submit_answer(int is_correct, int difficulty, int *out_score, int *out_rank);
void lobby_wait_barrier();

void lobby_reset_scores();
int lobby_save_score_and_get_total_rank(SSL *ssl, int score_gained, int *out_total_score);

int lobby_get_active_count();
int lobby_is_logged_in(const char *id);
void get_quiz_file_list(char *buffer, int size);
int lobby_get_current_q_idx();

#endif