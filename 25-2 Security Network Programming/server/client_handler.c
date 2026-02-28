#include "client_handler.h"
#include "account.h"
#include "quiz.h"
#include "lobby.h"
#include "util.h"
#include "die_with_message.h" 
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 

// [추가] 파일 업로드 처리 함수
void handle_upload(SSL *ssl, const char *line) {
    if (!lobby_is_admin(ssl)) {
        ssl_send(ssl, "ERR NotAdmin\n");
        return;
    }

    char filename[128];
    int filesize;
    if (sscanf(line, "UPLOAD %127s %d", filename, &filesize) != 2) {
        ssl_send(ssl, "ERR BadFormat\n");
        return;
    }

    ssl_send(ssl, "UPLOAD_READY\n"); // 클라이언트에게 전송 시작 신호

    char *filebuf = malloc(filesize);
    if (!filebuf) {
        PrintSystemError("malloc failed for upload");
        ssl_send(ssl, "ERR ServerMemory\n");
        return;
    }

    int received = ssl_read_bytes(ssl, filebuf, filesize);
    if (received != filesize) {
        PrintUserMessage("Upload", "Incomplete transfer");
        ssl_send(ssl, "ERR Incomplete\n");
        free(filebuf);
        return;
    }

    // 받은 평문 데이터를 암호화하여 저장
    if (encrypt_data_to_file(filename, filebuf, filesize) == 0) {
        PrintUserMessage("Upload", "File saved and encrypted.");
        ssl_send(ssl, "UPLOAD_OK\n");
    } else {
        PrintUserMessage("Upload", "Save failed");
        ssl_send(ssl, "ERR SaveFail\n");
    }
    free(filebuf);
}

void* client_thread(void *arg) {
    client_param_t *param = (client_param_t*)arg;
    SSL *ssl = param->ssl;
    int client_sock = param->sock; 
    
    char user_id[64] = {0}; 

    while (1) {
        int auth = handle_login_register(ssl, user_id); 
        if (auth < 0) { goto cleanup; }
        else if (auth == 0) continue; 
        else if (auth == 1) {
            if (lobby_is_logged_in(user_id)) {
                PrintUserMessage("Handler", "Blocked duplicate login");
                ssl_send(ssl, "ERR DuplicateLogin\n"); 
                goto cleanup;
            }
            account_confirm_login(user_id); 
            ssl_send(ssl, "LOGIN_OK\n");
            
            char msg[128]; sprintf(msg, "Login success: %s", user_id);
            PrintUserMessage("Handler", msg);
            break; 
        }
    }

    int idx = lobby_add(ssl, user_id);
    if (idx < 0) {
        ssl_send(ssl, "ERR LobbyFull\n");
        goto cleanup;
    }

    free(param);
    param = NULL; 

    char line[256];

    while (1) {
        int n = ssl_readline(ssl, line, sizeof(line));
        if (n <= 0) break; 

        if (!strncmp(line, "START", 5)) {
            lobby_handle_start_command(ssl, line);
            continue;
        }
        
        // [추가] UPLOAD 명령어 처리
        if (!strncmp(line, "UPLOAD", 6)) {
            handle_upload(ssl, line);
            // 업로드 후 로비 상태 갱신을 위해 방장 메뉴 재전송
            if (lobby_is_admin(ssl)) {
                ssl_send(ssl, "ADMIN_YOU_ARE_LEADER\n");
                char fl[1024]; get_quiz_file_list(fl, sizeof(fl));
                ssl_send(ssl, fl); ssl_send(ssl, "ADMIN_WAITING RESTART\n");
            }
            continue;
        }

        if (!strncmp(line, "ENTER", 5)) {
            run_quiz_session(ssl, idx, lobby_get_quiz_file());
            
            if (lobby_is_admin(ssl)) {
                ssl_send(ssl, "ADMIN_YOU_ARE_LEADER\n");
                char fl[1024];
                get_quiz_file_list(fl, sizeof(fl));
                ssl_send(ssl, fl);
                ssl_send(ssl, "ADMIN_WAITING RESTART\n");
            } else {
                ssl_send(ssl, "WAITING_FOR_START\n");
            }
            continue;
        }
    }

    lobby_remove(ssl);

cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (client_sock > 0) { close(client_sock); }
    if (param) { free(param); }
    return NULL;
}