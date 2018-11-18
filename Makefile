CC = g++
all: server client rmo

server: ikcp.o common.o server.o
	$(CC) -lmcrypt -lpthread bin/server.o bin/common.o bin/ikcp.o -o bin/server

client: ikcp.o common.o client.o
	$(CC) -lmcrypt -lpthread bin/client.o bin/common.o bin/ikcp.o -o bin/client

server.o: 
	$(CC) -c server.cpp -o bin/server.o

client.o: 
	$(CC) -c client.cpp -o bin/client.o

common.o: 
	$(CC) -c common.cpp -o bin/common.o

ikcp.o:
	gcc -c ikcp.c -o bin/ikcp.o

rmo:
	rm bin/*.o

clean:
	rm bin/*
