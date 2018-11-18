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
	if (bind(server_fd, (struct sockaddr *) &server, sizeof(server))) {
		logger("server")->info("udp bind() failed %s ", strerror(errno));
		exit(EXIT_FAILURE);
	}else{
        logger("server")->info("udp bind to :{}", SERVER_PORT);
    }
	return server_fd;
}

void handle(int dev_fd, int sock_fd)
{
    struct sockaddr_in client;

    kcpsess_st ps;
    ps.sock_fd = sock_fd;
    ps.dev_fd = dev_fd;
    ps.conv = 2004898;
    ps.dst = (struct sockaddr *) &client;
    ps.dst_len = sizeof(ps.dst);
    ikcpcb *kcp = init_kcp(&ps, 2);
    ps.kcp = kcp;

    std::thread udp2kcpt(udp2kcp, (void *)&ps);
    udp2kcpt.detach();
    std::thread dev2kcpt(dev2kcp, (void *)&ps);
    dev2kcpt.detach();
    std::thread kcp2devt(kcp2dev, (void *)&ps);
    kcp2devt.detach();
    while (true)
    {
        update_loop(&ps);
        isleep(1);
    }
}

int main(int argc, char *argv[])
{
    int sock_fd = listening();
    int dev_fd = init_tap();

    handle(dev_fd, sock_fd);

    logger("server")->info("close");
    close(sock_fd);
    close(dev_fd);

    return 0;

}