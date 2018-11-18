#include "common.h"

void handle(int dev_fd, int sock_fd, struct sockaddr *dst)
{
    kcpsess_st ps;
    ps.sock_fd = sock_fd;
    ps.dev_fd = dev_fd;
    ps.conv = 2004898;
    ps.dst = dst;
    ps.dst_len = sizeof(dst);
    ikcpcb *kcp = init_kcp(&ps, 2);
    ps.kcp = kcp;
    std::thread udp2kcpt(udp2kcp, (void *)&ps);
    udp2kcpt.detach();
    std::thread dev2kcpt(dev2kcp, (void *)&ps);
    dev2kcpt.detach();
    std::thread kcp2devt(kcp2dev, (void *)&ps);
    kcp2devt.detach();
    while (1)
    {
        update_loop(&ps);
        isleep(1);
    }
}

/*
		client: socket-->sendto-->revcfrom-->close
*/
int main(int argc, char *argv[])
{
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
    ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    ser_addr.sin_port = htons(SERVER_PORT);

    handle(dev_fd, sock_fd, (sockaddr *)&ser_addr);
    logger("client")->info("close");
    close(sock_fd);
    close(dev_fd);

    return 0;
}