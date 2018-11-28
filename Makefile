CC = gcc
all: server client testing rmo

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

deb:
	mkdir -p chroot/opt/sedge/vpn
	mkdir -p chroot/DEBIAN
	cp bin/server chroot/opt/sedge/vpn
	cp bin/client chroot/opt/sedge/vpn
	chmod +xs chroot/opt/sedge/vpn/client
	chmod +xs chroot/opt/sedge/vpn/server
	cp control chroot/DEBIAN/
	dpkg -b chroot sedge-vpn-0.1.0_amd64.deb
	rm -rf chroot

rmo:
	rm bin/*.o

clean:
	rm bin/*
