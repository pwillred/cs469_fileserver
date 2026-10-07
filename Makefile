# CS 469 Fileserver

CC := gcc
CFLAGS := -Wall -Wextra
LDFLAGS :=

SERVER_SRC := server.c server_ops.c server_util.c
SERVER_OBJS := $(SERVER_SRC:.c=.o)
SERVER := server

.PHONY: all clean

all: $(SERVER)

clean:
	rm -f $(SERVER_OBJS) $(SERVER)

$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto -lssl -lpthread

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^
