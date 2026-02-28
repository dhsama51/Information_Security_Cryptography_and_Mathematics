#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "die_with_message.h" 

#define PORT 9999
#define BUF 2048
#define ENC_KEY "01234567890123456789012345678901"
#define ENC_IV  "0123456789012345"
#define CLIENT_DB "client_users.db"

// (암호화 유틸리티 및 기타 함수들은 이전과 동일 - 생략 없이 전체 코드 제공)

int decrypt_file_to_mem(const char *filename, char **out_buf) {
    FILE *fp = fopen(filename, "rb"); if (!fp) return -1;
    fseek(fp, 0, SEEK_END); long fsize = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) { fclose(fp); return 0; }
    unsigned char *ciphertext = malloc(fsize);
    if (!ciphertext) { fclose(fp); return -1; }
    fread(ciphertext, 1, fsize, fp); fclose(fp);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)ENC_KEY, (unsigned char*)ENC_IV);
    unsigned char *plaintext = malloc(fsize + AES_BLOCK_SIZE + 1); 
    int len, plaintext_len;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, fsize)) { 
        free(ciphertext); free(plaintext); EVP_CIPHER_CTX_free(ctx); return -1; 
    }
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len); 
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx); free(ciphertext);
    plaintext[plaintext_len] = '\0'; *out_buf = (char*)plaintext;
    return plaintext_len;
}

int encrypt_data_to_file(const char *filename, const char *data, int data_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)ENC_KEY, (unsigned char*)ENC_IV);
    int out_len = data_len + AES_BLOCK_SIZE;
    unsigned char *ciphertext = malloc(out_len); int len, ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)data, data_len); ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    FILE *fp = fopen(filename, "wb"); 
    if(fp) { fwrite(ciphertext, 1, ciphertext_len, fp); fclose(fp); }
    free(ciphertext); return 0;
}

void bytes_to_hex(const unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; i++) {
        sprintf(out + i*2, "%02x", in[i]);
    }
    out[len*2] = '\0';
}

void hex_to_bytes(const char *hex, unsigned char *out, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(hex + i*2, "%2hhx", &out[i]);
    }
}

uint64_t hex_to_uint64(const char *hex) {
    uint64_t v = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex[i];
        int z = (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?10+c-'a':(c>='A'&&c<='F')?10+c-'A':0;
        v = (v << 4) | z;
    } return v;
}

int load_local(const char *id, uint64_t *R, uint64_t *counter) {
    char *data = NULL; int len = decrypt_file_to_mem(CLIENT_DB, &data);
    if (len < 0) return 0; 
    char *line = strtok(data, "\n");
    char rid[64], Rhex[17]; unsigned long long cnt;
    while(line) {
        if (sscanf(line, "%63s %16s %llu", rid, Rhex, &cnt) == 3 && strcmp(rid, id)==0) {
            *R = hex_to_uint64(Rhex); *counter = cnt; free(data); return 1;
        } line = strtok(NULL, "\n");
    } free(data); return 0;
}

void save_local(const char *id, uint64_t R, uint64_t counter) {
    char *data = NULL; int len = decrypt_file_to_mem(CLIENT_DB, &data);
    char big_buf[8192] = {0};
    if (len >= 0) {
        char *line = strtok(data, "\n");
        char rid[64], Rhex[17]; unsigned long long cnt;
        while (line) {
            sscanf(line, "%63s %16s %llu", rid, Rhex, &cnt);
            if (strcmp(rid, id) != 0) { 
                char t[128]; sprintf(t, "%s %s %llu\n", rid, Rhex, cnt); strcat(big_buf, t); 
            }
            line = strtok(NULL, "\n");
        } free(data);
    }
    char ent[128]; sprintf(ent, "%s %016llx %llu\n", id, (unsigned long long)R, (unsigned long long)counter); strcat(big_buf, ent);
    encrypt_data_to_file(CLIENT_DB, big_buf, strlen(big_buf));
}

int recv_line(SSL *ssl, char *buf, int sz) {
    int pos = 0;
    while (pos < sz - 1) {
        char c; int n = SSL_read(ssl, &c, 1);
        if (n <= 0) return -1;
        buf[pos++] = c; if (c == '\n') break;
    } buf[pos] = '\0'; return pos;
}

int perform_login(SSL *ssl, const char *id, const char *pw) {
    uint64_t R, counter;
    if (!load_local(id, &R, &counter)) { printf("[오류] 정보 없음. 회원가입 필요.\n"); return 0; }
    unsigned char pw_hash[32]; SHA256((unsigned char*)pw, strlen(pw), pw_hash);
    uint64_t V = R + counter; unsigned char Vbuf[8]; 
    for (int i=0; i<8; i++) Vbuf[7-i]=(V>>(i*8))&0xff;
    unsigned char calc[40]; memcpy(calc, pw_hash, 32); memcpy(calc+32, Vbuf, 8);
    unsigned char sess[32]; SHA256(calc, 40, sess);
    char phex[65], shex[65]; bytes_to_hex(pw_hash, 32, phex); bytes_to_hex(sess, 32, shex);
    char msg[512]; sprintf(msg, "LOGIN %s %s %s\n", id, phex, shex); SSL_write(ssl, msg, strlen(msg));
    char buf[256]; int n = recv_line(ssl, buf, sizeof(buf));
    if (n > 0 && strncmp(buf, "LOGIN_OK", 8) == 0) {
        printf(">> 로그인 성공! (Counter: %llu)\n", (unsigned long long)counter);
        save_local(id, R, counter+1); return 1;
    } else { printf(">> 로그인 실패: %s\n", buf); return 0; }
}

int handle_client_register(SSL *ssl, char *out_id, char *out_pw) {
    char sid[64]; printf("학번 입력(SID): "); scanf("%63s", sid);
    char msg[256]; sprintf(msg, "REGISTER %s\n", sid); SSL_write(ssl, msg, strlen(msg));
    char buf[1024]; int n = recv_line(ssl, buf, sizeof(buf));
    if (n <= 0 || strncmp(buf, "REGISTER_OK", 11) != 0) { printf("가입 실패: %s", buf); return 0; }
    printf("사용할 ID: "); scanf("%63s", out_id); printf("사용할 PW: "); scanf("%63s", out_pw);
    sprintf(msg, "CREATE %s %s\n", out_id, out_pw); SSL_write(ssl, msg, strlen(msg));
    n = recv_line(ssl, buf, sizeof(buf));
    char cmd[16], r[64];
    if (sscanf(buf, "%15s %63s", cmd, r)==2 && strcmp(cmd,"CREATE_OK")==0) {
        save_local(out_id, hex_to_uint64(r), 0); printf("회원가입 완료! (ID: %s)\n", out_id); return 1;
    } printf("가입 실패: %s", buf); return 0;
}

void upload_quiz_file(SSL *ssl) {
    char filepath[256];
    printf("업로드할 파일명(경로): ");
    scanf("%255s", filepath);

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        printf(">> 파일을 찾을 수 없습니다.\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *filebuf = malloc(filesize);
    if (!filebuf) {
        printf(">> 메모리 부족.\n");
        fclose(fp);
        return;
    }
    fread(filebuf, 1, filesize, fp);
    fclose(fp);

    char cmd[512];
    sprintf(cmd, "UPLOAD %s %ld\n", filepath, filesize);
    SSL_write(ssl, cmd, strlen(cmd));

    char buf[256];
    int n = recv_line(ssl, buf, sizeof(buf));
    if (n > 0 && strncmp(buf, "UPLOAD_READY", 12) == 0) {
        printf(">> 전송 중...\n");
        SSL_write(ssl, filebuf, filesize);
        
        n = recv_line(ssl, buf, sizeof(buf));
        if (n > 0 && strncmp(buf, "UPLOAD_OK", 9) == 0) {
            printf(">> 업로드 완료! (서버에 암호화되어 저장됨)\n");
        } else {
            printf(">> 서버 저장 실패: %s\n", buf);
        }
    } else {
        printf(">> 서버 거부: %s\n", buf);
    }
    free(filebuf);
}

void print_welcome() {
    printf("\n");
    printf("  _          _   _          ____        _       \n");
    printf(" | |    ___ | |_|_|__      / __ \\ _   _(_)____  \n");
    printf(" | |   / _ \\| __| / __|   | |  | | | | | |_  /  \n");
    printf(" | |__|  __/| |_  \\__ \\   | |__| | |_| | |/ /   \n");
    printf(" |_____\\___| \\__| |___/    \\___\\_\\ \\__,_|_/___| \n");
    printf("\n");
    printf("         Welcome to Security Programming Quiz!\n");
    printf("----------------------------------------------------\n");
}

void run_quiz_async(SSL *ssl, int sock) {
    printf("\n=== [QUIZ LOBBY] ===\n");
    char file_names[10][64]; int file_count = 0;
    int input_state = 0; 
    int remaining_time = 0; 

    while (1) {
        fd_set readfds; FD_ZERO(&readfds);
        FD_SET(sock, &readfds); FD_SET(STDIN_FILENO, &readfds);
        
        struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        struct timeval *ptv = (input_state == 2) ? &tv : NULL;

        int ret = select(sock + 1, &readfds, NULL, NULL, ptv);

        if (ret < 0) { PrintSystemError("select error"); break; }

        if (ret == 0 && input_state == 2) {
            remaining_time--;
            if (remaining_time > 0) {
                printf("\r\033[2K[⏳ 남은 시간: %d초] 정답(1~4): ", remaining_time);
                fflush(stdout); 
            }
            continue;
        }

        if (FD_ISSET(sock, &readfds)) {
            char buf[BUF]; int n = recv_line(ssl, buf, BUF);
            if (n <= 0) { printf("서버 연결 종료\n"); return; }

            if (!strncmp(buf, "LOBBY_COUNT", 11)) {
                int count = 0; sscanf(buf, "LOBBY_COUNT %d", &count);
                printf("\r\033[2K[Lobby] 현재 접속자 수: %d명\n", count); 
                if (input_state == 1) { printf("번호 입력 > "); fflush(stdout); }
                else if (input_state == 2) { 
                    printf("[⏳ 남은 시간: %d초] 정답(1~4): ", remaining_time); 
                    fflush(stdout); 
                }
            }
            else if (!strncmp(buf, "FILELIST", 8)) {
                file_count = 0; char *ptr = strtok(buf, " ");
                while ((ptr = strtok(NULL, " \r\n")) != NULL) {
                    if (file_count < 10) strcpy(file_names[file_count++], ptr);
                }
            }
            else if (!strncmp(buf, "ADMIN_YOU_ARE_LEADER", 20)) {
                printf("\n[ADMIN] 당신은 방장입니다!\n");
            }
            else if (!strncmp(buf, "ADMIN_WAITING", 13)) {
                if (file_count == 0) printf("[ADMIN] 퀴즈 파일 없음. 파일명 입력 > ");
                else {
                    printf("[ADMIN] 퀴즈 주제를 선택하세요:\n");
                    for(int i=0; i<file_count; i++) printf("  %d) %s\n", i+1, file_names[i]);
                    printf("  U) 새 퀴즈 파일 업로드\n");
                    printf("번호 또는 'U' 입력 > ");
                }
                fflush(stdout); input_state = 1;
            }
            else if (!strncmp(buf, "WAITING_FOR_START", 17)) {
                printf("게임 시작 대기 중...\n"); input_state = 0;
            }
            else if (!strncmp(buf, "ERR Min3Players", 15)) {
                int current_cnt; sscanf(buf, "ERR Min3Players %d", &current_cnt);
                printf("\n[!!!] 시작 불가: 현재 접속자 %d명 (최소 3명 필요)\n", current_cnt);
                printf("접속자를 기다리는 중... (다시 시도하려면 1번을 누르세요)\n");
            }
            else if (!strncmp(buf, "GAME_START", 10)) {
                printf("\n!!! 게임이 시작되었습니다 !!!\n");
                SSL_write(ssl, "ENTER\n", 6); input_state = 0;
            }
            else if (!strncmp(buf, "GIVEQ", 5)) {
                int q_num, evt;
                char q_text[512], op1[128], op2[128], op3[128], op4[128];
                char *p = strtok(buf, " ");
                p = strtok(NULL, "|"); q_num = p?atoi(p):0;
                p = strtok(NULL, "|"); if(p) strcpy(q_text, p);
                p = strtok(NULL, "|"); if(p) strcpy(op1, p);
                p = strtok(NULL, "|"); if(p) strcpy(op2, p);
                p = strtok(NULL, "|"); if(p) strcpy(op3, p);
                p = strtok(NULL, "|"); if(p) strcpy(op4, p);
                p = strtok(NULL, "\n"); evt = p?atoi(p):0;

                printf("\n-------------------------------------------------\n");
                printf("[문제 %d] %s [제한시간: 15초!]\n", q_num, q_text);
                if(evt) printf("★ EVENT 발동! 점수가 변동됩니다 ★\n");
                printf(" 1. %s\n 2. %s\n 3. %s\n 4. %s\n", op1, op2, op3, op4);
                printf("-------------------------------------------------\n");
                
                input_state = 2;
                remaining_time = 15;
                printf("[⏳ 남은 시간: %d초] 정답(1~4): ", remaining_time); 
                fflush(stdout); 
            }
            else if (!strncmp(buf, "GRADE", 5)) {
                int is_corr, corr_ans, score, q_rank, total, overall_rank;
                sscanf(buf, "GRADE %d %d %d %d %d %d", &is_corr, &corr_ans, &score, &q_rank, &total, &overall_rank);
                
                printf("\n"); 

                if (input_state == 2) { 
                    printf(">> 시간 초과... | 정답: %d번\n", corr_ans);
                } else {
                    if (is_corr) printf(">> 정답! (+%d점) | 문제 순위: %d위\n", score, q_rank);
                    else printf(">> 오답... (정답: %d번)\n", corr_ans);
                }
                
                printf(">> [현재 총점: %d점, 전체 순위: %d위]\n", total, overall_rank);
                input_state = 0;
            }
            else if (!strncmp(buf, "INFORMEND", 9)) {
                int final_score, record;
                sscanf(buf, "INFORMEND %d %d", &final_score, &record);
                printf("\n=== 퀴즈 종료 ===\n");
                printf("나의 최종 점수: %d점\n", final_score);
                printf("이 퀴즈의 역대 최고 기록: %d점\n", record);
                printf(">> 로비에서 대기합니다...\n");
                input_state = 0;
            }
            else if (!strncmp(buf, "UPLOAD_OK", 9)) {
                printf(">> 업로드 성공.\n");
            }
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            char line[128];
            if (fgets(line, sizeof(line), stdin) == NULL) break;
            line[strcspn(line, "\n")] = 0;

            if (input_state == 1) { 
                if (strcmp(line, "U") == 0 || strcmp(line, "u") == 0) {
                    upload_quiz_file(ssl);
                    input_state = 0; 
                } else {
                    int choice = atoi(line);
                    char fname[64];
                    if (file_count > 0 && choice >= 1 && choice <= file_count) strcpy(fname, file_names[choice-1]);
                    else if (file_count == 0 && strlen(line) > 0) strcpy(fname, line);
                    else strcpy(fname, "security_programming.q");
                    
                    char cmd[128]; sprintf(cmd, "START %s\n", fname);
                    SSL_write(ssl, cmd, strlen(cmd));
                    input_state = 0;
                }
            }
            else if (input_state == 2) { 
                if (strlen(line) == 0) continue; 
                int ans = atoi(line);
                if (ans < 1 || ans > 4) {
                    printf("\r\033[2K>> 1 ~ 4 사이의 숫자를 입력해주세요: "); fflush(stdout);
                    sleep(1); 
                    printf("\r\033[2K[⏳ 남은 시간: %d초] 정답(1~4): ", remaining_time); fflush(stdout);
                    continue; 
                }
                char msg[64]; sprintf(msg, "SUBMITA %d\n", ans);
                SSL_write(ssl, msg, strlen(msg));
                input_state = 0;
            }
        }
    }
}

int main() {
    SSL_library_init(); SSL_load_error_strings(); OpenSSL_add_all_algorithms();
    printf("서버 IP 입력: "); char ip[64]; scanf("%63s", ip);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0}; addr.sin_family = AF_INET; addr.sin_port = htons(PORT);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { 
        DieWithSystemMessage("connect() failed");
    }
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (SSL_CTX_load_verify_locations(ctx, "certificates/ca.crt", NULL)!=1) {
        DieWithOpenSSLError("Failed to load CA certificate");
    }
    
    SSL *ssl = SSL_new(ctx); SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) { 
        DieWithOpenSSLError("SSL_connect() failed");
    }
    
    printf("[Client] SSL handshake complete\n");

    print_welcome();

    printf("명령: 1)REGISTER 2)LOGIN : "); int sel; scanf("%d", &sel);
    char id[64]={0}, pw[64]={0}; int login_success = 0;
    
    if (sel==1) { if(handle_client_register(ssl, id, pw)) login_success=perform_login(ssl, id, pw); }
    else { printf("ID: "); scanf("%63s", id); printf("PW: "); scanf("%63s", pw); login_success=perform_login(ssl, id, pw); }
    
    if (login_success) run_quiz_async(ssl, sock); 
    else printf("종료.\n");

    if(ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if(sock>0) close(sock);
    if(ctx) SSL_CTX_free(ctx);
    EVP_cleanup(); 
    return 0;
}