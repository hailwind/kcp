CC = g++
all: server client rmo

server: ikcp.o common.o server.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/server.o bin/common.o bin/ikcp.o -o bin/server

client: ikcp.o common.o client.o
	$(CC) -g -rdynamic -lmcrypt -lpthread bin/client.o bin/common.o bin/ikcp.o -o bin/client

server.o: 
	$(CC) -g -rdynamic -c server.cpp -o bin/server.o

client.o: 
	$(CC) -g -rdynamic -c client.cpp -o bin/client.o

common.o: 
	$(CC) -g -rdynamic -c common.cpp -o bin/common.o

ikcp.o:
	gcc -g -rdynamic -c ikcp.c -o bin/ikcp.o

rmo:
	rm bin/*.o

clean:
	rm bin/*
