#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <mcrypt.h>
#include <netdb.h>
#include <pthread.h>

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include "map.h"
#include "common.h"

void test1(root_t *m, struct sockaddr_in server) {
    struct kcpsess_st kcps;
    kcps.conv=20045;
    //struct sockaddr_in server;
    kcps.dst = server;
    server.sin_port = 9999;
    server.sin_addr.s_addr = inet_addr("4.4.4.4");
    map_put(m, "testkey1", &kcps);
    printf("1-- kcps: %p, dst: %p\n", &kcps, kcps.dst.sin_addr);
}

void test2(root_t *m, struct kcpsess_st * kcps) {
    struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    kcps->dst = *server;
    kcps->conv = 10045;
    server->sin_port = 8888;
    server->sin_addr.s_addr = inet_addr("255.255.255.255");
    map_put(m, "testkey2", kcps);
    printf("2-- kcps: %p, dst: %p\n", kcps, kcps->dst);

}

int main(int argc, char *argv[])
{
    root_t m = RB_ROOT;
    struct sockaddr_in server;

    struct sockaddr_in client;
    client.sin_port = 7890;
    server = client;

    printf("X====== server: %p, port: %d, client: %p port: %d\n", &server, server.sin_port, &client, client.sin_port);

    test1(&m, server);

    struct kcpsess_st kcps;
    test2(&m, &kcps);

    map_t *node1 = map_get(&m, "testkey1");
    struct kcpsess_st *x = (struct kcpsess_st *) (node1->val);
    printf("3-- kcps: %p, conv: %d, dst: %p, port: %d\n", x, x->conv, x->dst, x->dst.sin_port);

    map_t *node2 = map_get(&m, "testkey2");
    struct kcpsess_st *y = (struct kcpsess_st *) (node2->val);
    printf("4-- kcps: %p, conv: %d, dst: %p, port: %d\n", y, y->conv, y->dst, y->dst.sin_port);

    printf("size1: %d size2: %d\n", sizeof(y->dst), sizeof(struct sockaddr_in));
    memcpy(&server, &y->dst, 6);

    printf("address: %s, port: %d\n", inet_ntoa(server.sin_addr), server.sin_port);

}