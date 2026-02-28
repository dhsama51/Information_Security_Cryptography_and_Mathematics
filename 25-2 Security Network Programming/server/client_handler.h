#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#include <openssl/ssl.h>

typedef struct {
    SSL *ssl;
    int sock;
} client_param_t;

void* client_thread(void* arg);

#endif
