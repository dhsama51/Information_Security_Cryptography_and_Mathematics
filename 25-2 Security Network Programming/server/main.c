#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "client_handler.h"
#include "account.h"
#include "die_with_message.h" // [추가]

#define PORT 9999

SSL_CTX* init_server_ctx() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); 
    if (!ctx) {
        DieWithOpenSSLError("Failed to create SSL_CTX"); // [수정]
    }

    if (SSL_CTX_use_certificate_file(ctx, "certificates/server.crt", SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(ctx, "certificates/server.key", SSL_FILETYPE_PEM) <= 0) 
    {
        DieWithOpenSSLError("Failed to load certificates"); // [수정]
    }

    return ctx;
}

int main() {
    load_users(); 
    printf("[Server] User DB loaded.\n");

    SSL_CTX *ctx = init_server_ctx(); 

    int serv_sock = socket(AF_INET, SOCK_STREAM, 0); 
    if (serv_sock < 0) DieWithSystemMessage("socket() failed"); // [수정]

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) // [수정]
        DieWithSystemMessage("bind() failed");

    if (listen(serv_sock, 5) < 0) // [수정]
        DieWithSystemMessage("listen() failed");

    printf("[Server] Listening on port %d...\n", PORT);

    while (1) {
        struct sockaddr_in caddr;
        socklen_t len = sizeof(caddr);

        int client_sock = accept(serv_sock, (struct sockaddr*)&caddr, &len); 
        if (client_sock < 0) {
            PrintSystemError("accept() failed"); // [수정] 서버 죽지 않게 Log만
            continue;
        }

        printf("[Server] Client connected: %s:%d\n",
               inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));

        SSL *ssl = SSL_new(ctx); 
        SSL_set_fd(ssl, client_sock); 

        if (SSL_accept(ssl) <= 0) { 
            PrintOpenSSLError("SSL_accept() failed"); // [수정]
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        client_param_t *param = malloc(sizeof(client_param_t)); 
        if (!param) {
            PrintSystemError("malloc() failed"); // [수정]
            SSL_free(ssl);
            close(client_sock);
            continue;
        }
        param->ssl  = ssl;
        param->sock = client_sock;

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, param) != 0) {
            PrintSystemError("pthread_create() failed"); // [수정]
            SSL_free(ssl);
            close(client_sock);
            free(param);
        } else {
            pthread_detach(tid);
        }
    }

    SSL_CTX_free(ctx);
    close(serv_sock);
    EVP_cleanup(); 
    return 0;
}