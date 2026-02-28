CC = gcc
CFLAGS = -Wall -I.
LIBS = -lssl -lcrypto

SRCS = client.c die_with_message.c
OBJS = $(SRCS:.c=.o)

TARGET = client

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TARGET)