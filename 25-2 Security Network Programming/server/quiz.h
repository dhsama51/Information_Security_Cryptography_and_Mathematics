#ifndef QUIZ_H
#define QUIZ_H

#include <openssl/ssl.h>

#define MAX_Q 100
#define MAX_LEN 512

typedef struct {
    char question[MAX_LEN];
    char options[4][MAX_LEN];
    int correct;
    int difficulty; // [추가] 난이도 (1:하, 2:중, 3:상)
} Quiz;

int LoadQuizFile(const char *filename);
void run_quiz_session(SSL *ssl, int user_id, const char *filename);
void ShuffleQuiz();

#endif