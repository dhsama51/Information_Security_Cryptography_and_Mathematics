CC = gcc
CFLAGS = -Wall -I.
LIBS = -lssl -lcrypto -lpthread

# 서버 실행에 필요한 소스 파일들
SRCS = main.c client_handler.c account.c quiz.c util.c lobby.c die_with_message.c
OBJS = $(SRCS:.c=.o)

TARGET = server

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

# .c 파일을 .o 파일로 컴파일하는 규칙
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)