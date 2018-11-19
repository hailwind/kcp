#include "common.h"

static int listening()
{
    struct sockaddr_in server;
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0)
    {
        logger("server")->info("create socket fail!");
        exit(EXIT_FAILURE);
    }

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(SERVER_PORT);
    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)))
    {
        logger("server")->info("udp bind() failed {}", strerror(errno));
        exit(EXIT_FAILURE);
    }
    else
    {
        logger("server")->info("udp bind to :{}", SERVER_PORT);
    }
    return server_fd;
}

void handle(int dev_fd, int sock_fd)
{
    struct sockaddr_in client;
    struct kcpsess_st ps;
    ps.sock_fd = sock_fd;
    ps.dev_fd = dev_fd;
    ps.conv = 2004898;
    ps.dst = (struct sockaddr *)&client;
    ps.dst_len = sizeof(ps.dst);
    ikcpcb *kcp = init_kcp(&ps, 2);
    ps.kcp = kcp;
    pthread_t udp2kcpt, dev2kcpt, kcp2devt;

    pthread_create(&udp2kcpt, NULL, udp2kcp, (void *)&ps);
    pthread_detach(udp2kcpt);

    pthread_create(&dev2kcpt, NULL, dev2kcp, (void *)&ps);
    pthread_detach(dev2kcpt);

    pthread_create(&kcp2devt, NULL, kcp2dev, (void *)&ps);
    pthread_detach(kcp2devt);

    update_loop(&ps);
}

int main(int argc, char *argv[])
{
    if (argc != 1 && argc != 3)
    {
        printf("server [twofish] [cbc]\n");
        exit(0);
    }
    if (argc == 3)
    {
        algo = argv[1];
        mode = argv[2];
    }
    int sock_fd = listening();
    int dev_fd = init_tap();
    handle(dev_fd, sock_fd);
    logger("server")->info("close");
    close(sock_fd);
    close(dev_fd);
    return 0;
}