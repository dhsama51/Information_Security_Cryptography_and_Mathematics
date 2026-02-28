#include "account.h"
#include "util.h"
#include "die_with_message.h" // [추가]
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#define MAX_USERS   100
#define MAX_ID_LEN  64
#define MAX_PW_LEN  64

static const char* VALID_SIDS[] = { "20212052", "20232106", "20225158", "10000000" }; 
static const int VALID_SID_COUNT = 4;

typedef struct {
    int used;
    char sid[16];
    char id[MAX_ID_LEN];
    unsigned char pw_hash[32]; 
    uint64_t R;                
    uint64_t counter;          
} User;

static User g_users[MAX_USERS];
static const char* USER_DB = "users.db";

void hex_to_bytes(const char *hex, unsigned char *out, int outlen) {
    for (int i = 0; i < outlen; i++) sscanf(hex + i*2, "%2hhx", &out[i]);
}
void bytes_to_hex(const unsigned char *in, int inlen, char *out) {
    for (int i = 0; i < inlen; i++) sprintf(out + i*2, "%02x", in[i]);
    out[inlen*2] = '\0';
}
uint64_t hex_to_uint64(const char *hex) {
    uint64_t v = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex[i];
        int val = 0;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');
        v = (v << 4) | val;
    }
    return v;
}
void uint64_to_hex(uint64_t v, char *out) {
    sprintf(out, "%016llx", (unsigned long long)v);
}

void load_users() { 
    char *data = NULL;
    int len = decrypt_file_to_mem(USER_DB, &data);
    
    if (len < 0) {
        PrintUserMessage("Account", "Encrypted load failed, trying plain text..."); // [수정]
        FILE *fp = fopen(USER_DB, "r");
        if (!fp) return;
        
        char sid[16], id[64], pw_hex[65], R_hex[17];
        unsigned long long counter;
        while (fscanf(fp, "%15s %63s %64s %16s %llu", sid, id, pw_hex, R_hex, &counter) == 5) {
            for (int i = 0; i < MAX_USERS; i++) {
                if (!g_users[i].used) {
                    User *u = &g_users[i];
                    u->used = 1; strcpy(u->sid, sid); strcpy(u->id, id);
                    hex_to_bytes(pw_hex, u->pw_hash, 32); u->R = hex_to_uint64(R_hex); u->counter = counter;
                    break;
                }
            }
        }
        fclose(fp);
    } else {
        PrintUserMessage("Account", "Encrypted DB loaded successfully."); // [수정]
        char sid[16], id[64], pw_hex[65], R_hex[17];
        unsigned long long counter;
        
        char *line = strtok(data, "\n");
        while(line != NULL) {
            if (sscanf(line, "%15s %63s %64s %16s %llu", sid, id, pw_hex, R_hex, &counter) == 5) {
                for (int i = 0; i < MAX_USERS; i++) {
                    if (!g_users[i].used) {
                        User *u = &g_users[i];
                        u->used = 1; strcpy(u->sid, sid); strcpy(u->id, id);
                        hex_to_bytes(pw_hex, u->pw_hash, 32); u->R = hex_to_uint64(R_hex); u->counter = counter;
                        break;
                    }
                }
            }
            line = strtok(NULL, "\n");
        }
        free(data);
    }
}

void save_users() { 
    char *big_buf = malloc(MAX_USERS * 512); 
    if (!big_buf) {
        PrintSystemError("malloc failed in save_users"); // [수정]
        return;
    }
    big_buf[0] = '\0';

    for (int i = 0; i < MAX_USERS; i++) {
        if (!g_users[i].used) continue;
        User *u = &g_users[i];
        char pw_hex[65], R_hex[17];
        bytes_to_hex(u->pw_hash, 32, pw_hex);
        uint64_to_hex(u->R, R_hex);
        
        char line[512];
        sprintf(line, "%s %s %s %s %llu\n", u->sid, u->id, pw_hex, R_hex, (unsigned long long)u->counter);
        strcat(big_buf, line);
    }

    if(encrypt_data_to_file(USER_DB, big_buf, strlen(big_buf)) < 0) {
        PrintUserMessage("Account", "Failed to save encrypted DB"); // [수정]
    }
    free(big_buf);
}

int valid_sid(const char *sid) {
    for (int i = 0; i < VALID_SID_COUNT; i++) if (strcmp(sid, VALID_SIDS[i]) == 0) return 1;
    return 0;
}
int valid_id(const char *id) {
    int len = strlen(id);
    if (len < 4 || len > 20) return 0;
    for (int i = 0; i < len; i++) if (!isalnum((unsigned char)id[i])) return 0;
    return 1;
}
int valid_pw(const char *pw) {
    int len = strlen(pw);
    return (len >= 8 && len <= 32);
}

static int handle_register(SSL *ssl, const char *line) {
    char sid[16];
    if (sscanf(line, "REGISTER %15s", sid) != 1) { 
        PrintUserMessage("Register", "Invalid format"); // [수정] 로그 추가
        ssl_send(ssl, "REGISTER_FAIL Invalid\n"); 
        return -1; 
    } 
    if (!valid_sid(sid)) { 
        PrintUserMessage("Register", "Invalid SID"); // [수정]
        ssl_send(ssl, "REGISTER_FAIL InvalidSID\n"); 
        return -1; 
    }
    for (int i = 0; i < MAX_USERS; i++) {
        if (g_users[i].used && strcmp(g_users[i].sid, sid) == 0) { 
            PrintUserMessage("Register", "SID already used"); // [수정]
            ssl_send(ssl, "REGISTER_FAIL SIDUsed\n"); 
            return -1; 
        } 
    }
    ssl_send(ssl, "REGISTER_OK\n"); 

    char buf[256];
    if (ssl_readline(ssl, buf, sizeof(buf)) <= 0) return -1;
    char cmd[16], id[MAX_ID_LEN], pw[MAX_PW_LEN];
    if (sscanf(buf, "%15s %63s %63s", cmd, id, pw) != 3 || strcmp(cmd,"CREATE")!=0) { 
        PrintUserMessage("Register", "CREATE format error"); // [수정]
        ssl_send(ssl, "CREATE_FAIL InvalidFormat\n"); 
        return -1; 
    } 
    if (!valid_id(id) || !valid_pw(pw)) { 
        PrintUserMessage("Register", "Invalid ID/PW rules"); // [수정]
        ssl_send(ssl, "CREATE_FAIL InvalidIDPW\n"); 
        return -1; 
    } 

    unsigned char pw_hash[32];
    SHA256((unsigned char*)pw, strlen(pw), pw_hash); 

    for (int i = 0; i < MAX_USERS; i++) {
        if (!g_users[i].used) {
            User *u = &g_users[i];
            u->used = 1; strcpy(u->sid, sid); strcpy(u->id, id);
            memcpy(u->pw_hash, pw_hash, 32);
            RAND_bytes((unsigned char*)&u->R, sizeof(uint64_t)); 
            u->counter = 0;
            save_users();
            char R_hex[17]; uint64_to_hex(u->R, R_hex);
            char out[64]; sprintf(out, "CREATE_OK %s\n", R_hex);
            ssl_send(ssl, out); 
            return 0; 
        }
    }
    PrintUserMessage("Register", "No user slots available"); // [수정]
    ssl_send(ssl, "CREATE_FAIL NoSlot\n"); 
    return -1;
}

static int handle_login(SSL *ssl, const char *line, char *out_id) {
    char id[64], pw_hash_hex[65], sess_hash_hex[65];
    if (sscanf(line, "LOGIN %63s %64s %64s", id, pw_hash_hex, sess_hash_hex) != 3) { 
        PrintUserMessage("Login", "Bad format"); // [수정]
        ssl_send(ssl, "LOGIN_FAIL BadFormat\n"); return -1;
    }

    User *u = NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (g_users[i].used && strcmp(g_users[i].id, id) == 0) { 
            u = &g_users[i]; break;
        }
    }
    if (!u) { 
        PrintUserMessage("Login", "User not found"); // [수정]
        ssl_send(ssl, "LOGIN_FAIL NoUser\n"); return -1; 
    } 

    unsigned char pw_hash_client[32], sess_hash_client[32];
    hex_to_bytes(pw_hash_hex, pw_hash_client, 32);
    hex_to_bytes(sess_hash_hex, sess_hash_client, 32);

    if (memcmp(pw_hash_client, u->pw_hash, 32)!=0) { 
        PrintUserMessage("Login", "Wrong Password Hash"); // [수정]
        ssl_send(ssl, "LOGIN_FAIL WrongPWHash\n"); return -1; 
    } 
 
    uint64_t V = u->R + u->counter; 
    unsigned char Vbuf[8];
    for (int i = 0; i < 8; i++) Vbuf[7-i] = (V >> (i*8)) & 0xff; 
    unsigned char calc_in[40];
    memcpy(calc_in, u->pw_hash, 32); memcpy(calc_in+32, Vbuf, 8);
    unsigned char sess_hash_srv[32];
    SHA256(calc_in, 40, sess_hash_srv); 

    if (memcmp(sess_hash_srv, sess_hash_client, 32)!=0) { 
        PrintUserMessage("Login", "Session Hash Mismatch"); // [수정]
        ssl_send(ssl, "LOGIN_FAIL WrongSession\n"); return -1; 
    } 

    if (out_id) strcpy(out_id, id); 

    return 1;
}

void account_confirm_login(const char *id) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (g_users[i].used && strcmp(g_users[i].id, id) == 0) { 
            g_users[i].counter++; 
            save_users();         
            break;
        }
    }
}

int handle_login_register(SSL *ssl, char *out_id) {
    char buf[256];
    if (ssl_readline(ssl, buf, sizeof(buf)) <= 0) return -1;

    if (!strncmp(buf,"REGISTER",8)) return handle_register(ssl, buf);
    if (!strncmp(buf,"LOGIN",5)) return handle_login(ssl, buf, out_id);

    PrintUserMessage("Auth", "Unknown command"); // [수정]
    ssl_send(ssl, "ERR UnknownCmd\n");
    return -1;
}