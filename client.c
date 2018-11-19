#include "common.h"

void handle(int dev_fd, int sock_fd, struct sockaddr *dst)
{
    struct kcpsess_st ps;
    ps.sock_fd = sock_fd;
    ps.dev_fd = dev_fd;
    ps.conv = 2004898;
    ps.dst = dst;
    ps.dst_len = sizeof(dst);
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
    if (argc < 2)
    {
        printf("client 192.168.1.1 [twofish] [cbc]\n");
        exit(0);
    }
    if (argc == 4)
    {
        algo = argv[2];
        mode = argv[3];
    }
    int dev_fd = init_tap();
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        logger("client")->info("create socket fail!");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in ser_addr;
    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(argv[1]);
    ser_addr.sin_port = htons(SERVER_PORT);
    handle(dev_fd, sock_fd, (struct sockaddr *)&ser_addr);
    logger("client")->info("close");
    close(sock_fd);
    close(dev_fd);

    return 0;
}