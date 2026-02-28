#include "lobby.h"
#include "util.h"
#include "quiz.h"
#include "die_with_message.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <dirent.h> 

static LobbyClient clients[MAX_CLIENTS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char current_quiz_filename[256] = "security_programming.q";

static int admin_index = -1;
static int game_started = 0;
static int current_q_idx = 0; 
static int total_quiz_count = 0;

static pthread_mutex_t submit_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cond = PTHREAD_COND_INITIALIZER;
static int submission_count = 0;        
static int correct_submission_count = 0; 
static int barrier_count = 0;           

void lobby_init() {
    memset(clients, 0, sizeof(clients));
    admin_index = -1;
    game_started = 0;
    current_q_idx = 0; 
    total_quiz_count = 0;
    strcpy(current_quiz_filename, "security_programming.q");
    submission_count = 0;
    correct_submission_count = 0; 
    barrier_count = 0;
}

int lobby_get_current_q_idx() { return current_q_idx; }
void lobby_reset_scores() {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_CLIENTS; i++) { if (clients[i].used) clients[i].score = 0; }
    pthread_mutex_unlock(&lock);
}
int lobby_save_score_and_get_total_rank(SSL *ssl, int score_gained, int *out_total_score) {
    pthread_mutex_lock(&lock);
    int my_total = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].used && clients[i].ssl == ssl) {
            clients[i].score += score_gained; my_total = clients[i].score; break;
        }
    }
    if (out_total_score) *out_total_score = my_total;
    int rank = 1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].used && clients[i].ssl != ssl) {
            if (clients[i].score > my_total) rank++;
        }
    }
    pthread_mutex_unlock(&lock);
    return rank;
}

int count_questions_in_file(const char *filename) {
    char *data = NULL;
    int len = decrypt_file_to_mem(filename, &data);
    int count = 0;
    if (len >= 0) {
        for (int i = 0; i < len; i++) if (data[i] == '\n') count++;
        if (len > 0 && data[len-1] != '\n') count++;
        free(data);
    } else {
        FILE *fp = fopen(filename, "r");
        if (!fp) return 0;
        char buf[2048];
        while (fgets(buf, sizeof(buf), fp)) if (strlen(buf) > 5) count++;
        fclose(fp);
    }
    return count;
}

void get_quiz_file_list(char *buffer, int size) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    strcpy(buffer, "FILELIST"); 
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            char *dot = strrchr(dir->d_name, '.');
            if (dot && strcmp(dot, ".q") == 0) {
                int q_cnt = count_questions_in_file(dir->d_name);
                char temp[512]; 
                sprintf(temp, " %s(%d문제)", dir->d_name, q_cnt);
                strcat(buffer, temp);
            }
        }
        closedir(d);
    }
    strcat(buffer, "\n");
}

int lobby_get_active_count() {
    pthread_mutex_lock(&lock);
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].used) count++;
    pthread_mutex_unlock(&lock);
    return count;
}

int lobby_is_logged_in(const char *id) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].used && strcmp(clients[i].id, id) == 0) {
            pthread_mutex_unlock(&lock);
            return 1; 
        }
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

void broadcast_lobby_count() {
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].used) count++;
    char msg[64];
    sprintf(msg, "LOBBY_COUNT %d\n", count);
    for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].used) ssl_send(clients[i].ssl, msg);
}

int lobby_add(SSL *ssl, const char *id) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].used) {
            clients[i].used = 1;
            clients[i].ssl = ssl;
            clients[i].score = 0; 
            strncpy(clients[i].id, id, 63);
            clients[i].id[63] = '\0';

            broadcast_lobby_count();

            if (admin_index == -1) {
                admin_index = i;
                ssl_send(ssl, "ADMIN_YOU_ARE_LEADER\n");
                char fl[1024];
                get_quiz_file_list(fl, sizeof(fl));
                ssl_send(ssl, fl);
                ssl_send(ssl, "ADMIN_WAITING START_CMD\n");
            } else {
                if (!game_started) ssl_send(ssl, "WAITING_FOR_START\n");
                else ssl_send(ssl, "GAME_START\n"); 
            }
            pthread_mutex_unlock(&lock);
            return i;
        }
    }
    pthread_mutex_unlock(&lock);
    return -1;
}

void lobby_remove(SSL *ssl) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].used && clients[i].ssl == ssl) {
            clients[i].used = 0;
            memset(clients[i].id, 0, 64); 
            broadcast_lobby_count();
            if (admin_index == i) {
                admin_index = -1;
                for (int k = 0; k < MAX_CLIENTS; k++) {
                    if (clients[k].used) {
                        admin_index = k;
                        ssl_send(clients[k].ssl, "ADMIN_YOU_ARE_LEADER\n");
                        char fl[1024];
                        get_quiz_file_list(fl, sizeof(fl));
                        ssl_send(clients[k].ssl, fl);
                        ssl_send(clients[k].ssl, "ADMIN_WAITING START_CMD\n");
                        break;
                    }
                }
            }
            break;
        }
    }
    pthread_mutex_unlock(&lock);
}

int lobby_is_admin(SSL *ssl) {
    pthread_mutex_lock(&lock);
    int res = (admin_index != -1 && clients[admin_index].ssl == ssl);
    pthread_mutex_unlock(&lock);
    return res;
}

void lobby_broadcast(const char *msg) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].used) ssl_send(clients[i].ssl, msg);
    pthread_mutex_unlock(&lock);
}

void lobby_handle_start_command(SSL *ssl, const char *msg) {
    if (strncmp(msg, "START", 5) != 0) return;
    if (!lobby_is_admin(ssl)) { ssl_send(ssl, "ERR NotAdmin\n"); return; }

    int active_users = lobby_get_active_count();
    if (active_users < 3) {
        char log_msg[128]; sprintf(log_msg, "Start failed: Only %d users", active_users);
        PrintUserMessage("Lobby", log_msg); 
        char err_msg[128]; sprintf(err_msg, "ERR Min3Players %d\n", active_users);
        ssl_send(ssl, err_msg);
        char fl[1024]; get_quiz_file_list(fl, sizeof(fl));
        ssl_send(ssl, fl); ssl_send(ssl, "ADMIN_WAITING RETRY\n"); 
        return; 
    }

    char buf[256];
    strncpy(buf, msg, sizeof(buf));
    char *ptr = strtok(buf, " \r\n");
    ptr = strtok(NULL, " \r\n");

    pthread_mutex_lock(&lock);
    if (ptr && strlen(ptr) > 0) {
        char *paren = strchr(ptr, '(');
        if (paren) *paren = '\0';
        strncpy(current_quiz_filename, ptr, sizeof(current_quiz_filename)-1);
        current_quiz_filename[sizeof(current_quiz_filename)-1] = '\0';
    }

    char log_msg[512]; sprintf(log_msg, "Admin START. Loading file: %s", current_quiz_filename);
    PrintUserMessage("Lobby", log_msg);

    int q_count = LoadQuizFile(current_quiz_filename);
    
    if (q_count <= 0) {
        ssl_send(ssl, "ERR LoadFileFail\n");
        pthread_mutex_unlock(&lock);
        return;
    }

    game_started = 1;
    current_q_idx = 0; 
    total_quiz_count = q_count; 

    pthread_mutex_unlock(&lock);
    lobby_reset_scores();
    lobby_broadcast("GAME_START\n");
}

void lobby_wait_for_start(SSL *ssl) {
    if (game_started) return;
    ssl_send(ssl, "WAITING_FOR_START\n");
}

const char* lobby_get_quiz_file() {
    return current_quiz_filename;
}

// [수정] 난이도 반영 점수 계산
void lobby_submit_answer(int is_correct, int difficulty, int *out_score, int *out_rank) {
    pthread_mutex_lock(&submit_mutex);
    int total_users = 0;
    for(int i=0; i<MAX_CLIENTS; i++) if(clients[i].used) total_users++;

    submission_count++; 
    int rank = 0;
    int score = 0;

    if (is_correct) {
        correct_submission_count++;
        rank = correct_submission_count;
        // [수정] 점수 공식: 난이도 * (전체인원 - 순위 + 1)
        score = difficulty * (total_users - rank + 1);
    } else {
        score = 0; 
        rank = 0;
    }
    *out_score = score;
    *out_rank = rank;
    pthread_mutex_unlock(&submit_mutex);
}

void lobby_wait_barrier() {
    pthread_mutex_lock(&submit_mutex);
    barrier_count++;
    int total_users = 0;
    for(int i=0; i<MAX_CLIENTS; i++) if(clients[i].used) total_users++;

    if (barrier_count >= total_users) {
        barrier_count = 0;
        submission_count = 0; 
        correct_submission_count = 0; 
        
        current_q_idx++; 
        
        if (current_q_idx >= total_quiz_count) {
            game_started = 0;
            PrintUserMessage("Lobby", "All questions finished. Game Reset.");
        }

        pthread_cond_broadcast(&barrier_cond);
    } else {
        pthread_cond_wait(&barrier_cond, &submit_mutex);
    }
    pthread_mutex_unlock(&submit_mutex);
}