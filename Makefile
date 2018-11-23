CC = gcc
all: server client testing

server: common.o server.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/server.o bin/common.o bin/ikcp.o bin/rbtree.o -o bin/server

client: common.o client.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/client.o bin/common.o bin/ikcp.o bin/rbtree.o -o bin/client

testing: rbtree.o testing.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/testing.o bin/rbtree.o -o bin/testing

testing.o: 
	$(CC) -g -rdynamic -c testing.c -o bin/testing.o

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
