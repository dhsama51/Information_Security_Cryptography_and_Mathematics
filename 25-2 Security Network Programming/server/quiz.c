#include "quiz.h"
#include "util.h"
#include "lobby.h" 
#include "die_with_message.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h> 
#include <time.h> 
#include <openssl/ssl.h>
#include <pthread.h> 

#define MAX_Q 100
#define MAX_LEN 512
#define QUIZ_TIMEOUT 15 

static pthread_mutex_t highscore_mutex = PTHREAD_MUTEX_INITIALIZER;
static Quiz quizList[MAX_Q];
static int quizCount = 0;

void trim(char *str) { 
    if (!str) return;
    int len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

void ShuffleQuiz() {
    if (quizCount <= 1) return;
    srand(time(NULL));
    for (int i = quizCount - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        Quiz temp = quizList[i];
        quizList[i] = quizList[j];
        quizList[j] = temp;
    }
    PrintUserMessage("Quiz", "Shuffled questions.");
}

void ParseLine(char *line) {
    if (quizCount >= MAX_Q) return;
    trim(line);
    if (strlen(line) < 5) return;
    
    char *token = strtok(line, "|");
    char *tokens[7] = {0}; 
    int idx = 0;
    while (token != NULL && idx < 7) {
        tokens[idx++] = token;
        token = strtok(NULL, "|");
    }
    if (idx < 6) return; 

    strncpy(quizList[quizCount].question, tokens[0], MAX_LEN);
    strncpy(quizList[quizCount].options[0], tokens[1], MAX_LEN);
    strncpy(quizList[quizCount].options[1], tokens[2], MAX_LEN);
    strncpy(quizList[quizCount].options[2], tokens[3], MAX_LEN);
    strncpy(quizList[quizCount].options[3], tokens[4], MAX_LEN);
    trim(tokens[5]);
    quizList[quizCount].correct = atoi(tokens[5]);
    
    if (idx >= 7) {
        trim(tokens[6]);
        quizList[quizCount].difficulty = atoi(tokens[6]);
        if (quizList[quizCount].difficulty < 1) quizList[quizCount].difficulty = 1;
        if (quizList[quizCount].difficulty > 3) quizList[quizCount].difficulty = 3;
    } else {
        quizList[quizCount].difficulty = 1;
    }

    quizCount++;
}

int LoadQuizFile(const char *filename) {
    char *data = NULL;
    int len = decrypt_file_to_mem(filename, &data);
    quizCount = 0;
    if (len >= 0) {
        PrintUserMessage("Quiz", "Decrypted file loaded.");
        char *cursor = data;
        char *line_start = data;
        while (*cursor != '\0' && quizCount < MAX_Q) {
            if (*cursor == '\n') {
                *cursor = '\0';
                ParseLine(line_start);
                line_start = cursor + 1;
            }
            cursor++;
        }
        if (line_start < cursor) ParseLine(line_start);
        free(data);
        ShuffleQuiz();
        return quizCount;
    }
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        char msg[256]; sprintf(msg, "Cannot open file: %s", filename);
        PrintUserMessage("Quiz", msg); 
        return -1;
    }
    char buffer[2048];
    char *full_content = malloc(1024 * 100); 
    if(full_content) full_content[0] = '\0';

    while (fgets(buffer, sizeof(buffer), fp) != NULL && quizCount < MAX_Q) {
        if(full_content) strcat(full_content, buffer);
        char line_copy[2048];
        strcpy(line_copy, buffer);
        ParseLine(line_copy);
    }
    fclose(fp);

    if (quizCount > 0 && full_content) {
        encrypt_data_to_file(filename, full_content, strlen(full_content));
        PrintUserMessage("Quiz", "Plain text file encrypted and saved.");
    }
    if(full_content) free(full_content);

    ShuffleQuiz();
    return quizCount;
}

void SendToClient(SSL *ssl, const char *msg) {
    ssl_send(ssl, msg);
}

void run_quiz_session(SSL *ssl, int user_id, const char *filename) {
    if (quizCount <= 0) {
         SendToClient(ssl, "ERR QuizNotLoaded\n");
         return;
    }

    int start_index = lobby_get_current_q_idx();
    if (start_index >= quizCount) {
        pthread_mutex_lock(&highscore_mutex);
        int rh = get_high_score(filename);
        pthread_mutex_unlock(&highscore_mutex);
        char endmsg[256];
        sprintf(endmsg, "INFORMEND 0 %d\n", rh);
        SendToClient(ssl, endmsg);
        return;
    }

    char msg[256];
    sprintf(msg, "INFORMSTART QuizTopic %d %d 1\n", quizCount, 0);
    SendToClient(ssl, msg);

    int my_total_score = 0;

    for (int i = start_index; i < quizCount; i++) {
        char qmsg[4096];
        const char *diff_str = (quizList[i].difficulty==3)?"[상]":(quizList[i].difficulty==2)?"[중]":"[하]";
        char q_text_with_diff[1024];
        sprintf(q_text_with_diff, "%s %s", diff_str, quizList[i].question);

        sprintf(qmsg, "GIVEQ %d|%s|%s|%s|%s|%s|0\n",
                i+1, q_text_with_diff,
                quizList[i].options[0], quizList[i].options[1],
                quizList[i].options[2], quizList[i].options[3]);
        SendToClient(ssl, qmsg);

        char buf[128];
        int selection = -1;
        int read_ret = ssl_readline_timeout(ssl, buf, sizeof(buf), QUIZ_TIMEOUT);
        
        if (read_ret == -2) { selection = -1; } 
        else if (read_ret > 0) {
            trim(buf);
            if (strncmp(buf, "SUBMITA", 7) == 0) {
                int parsed_sel = -1;
                if (sscanf(buf, "SUBMITA %d", &parsed_sel) == 1) selection = parsed_sel;
            }
        } else { selection = -1; }

        int correct = quizList[i].correct;
        int is_correct = (selection == correct);
        
        int score_gained = 0;
        int q_rank = 0;
        
        lobby_submit_answer(is_correct, quizList[i].difficulty, &score_gained, &q_rank);
        
        int overall_rank = lobby_save_score_and_get_total_rank(ssl, score_gained, &my_total_score);

        char gr[128];
        sprintf(gr, "GRADE %d %d %d %d %d %d\n",
                is_correct, correct, score_gained, q_rank, my_total_score, overall_rank);
        SendToClient(ssl, gr);

        lobby_wait_barrier();
    }

    // [수정] 1. 모든 문제 종료 후 배리어 (이미 루프 끝에서 대기했으므로 여기선 생략 가능하지만, 안전상 추가)
    // 현재 구조상 루프 마지막 lobby_wait_barrier()가 이를 대신함.

    // [수정] 2. 점수 업데이트 (Mutex 보호)
    pthread_mutex_lock(&highscore_mutex);
    update_high_score(filename, my_total_score);
    pthread_mutex_unlock(&highscore_mutex);

    // [중요] 3. 모든 스레드가 업데이트를 마칠 때까지 대기 (Race Condition 해결)
    // 이 배리어가 있어야 늦게 끝난 사람이 업데이트한 점수를 일찍 끝난 사람도 볼 수 있음
    lobby_wait_barrier();

    // [수정] 4. 이제 안전하게 읽기 (모두가 업데이트를 마친 상태)
    pthread_mutex_lock(&highscore_mutex); // 읽기 락 (쓰기와 보호)
    int record_high = get_high_score(filename);
    pthread_mutex_unlock(&highscore_mutex);

    char endmsg[256];
    sprintf(endmsg, "INFORMEND %d %d\n", my_total_score, record_high);
    SendToClient(ssl, endmsg);

    char finish_msg[64]; sprintf(finish_msg, "Session finished for user %d.", user_id);
    PrintUserMessage("Quiz", finish_msg);
}