CC = gcc
all: server client

server: common.o server.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/server.o bin/common.o bin/ikcp.o bin/rbtree.o -o bin/server

client: common.o client.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/client.o bin/common.o bin/ikcp.o bin/rbtree.o -o bin/client

server.o: 
	$(CC) -g -rdynamic -c server.c -o bin/server.o

client.o: 
	$(CC) -g -rdynamic -c client.c -o bin/client.o

common.o:  rbtree.o ikcp.o 
	$(CC) -g -rdynamic -c common.c -o bin/common.o

ikcp.o:
	$(CC) -g -rdynamic -c ikcp.c -o bin/ikcp.o

rbtree.o:
	$(CC) -g -rdynamic -c rbtree.c -o bin/rbtree.o

rmo:
	rm bin/*.o

clean:
	rm bin/*
