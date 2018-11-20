#include "common.h"
#include <getopt.h>

static int listening(int port)
{
    struct sockaddr_in server;
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0)
    {
        logging("listening", "create socket fail!");
        exit(EXIT_FAILURE);
    }

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)))
    {
        logging("listening", "udp bind() failed %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    else
    {
        logging("listening", "udp bind to :%d", port);
    }
    return server_fd;
}

void handle(int dev_fd, int sock_fd, int conv)
{
    struct sockaddr_in client;
    struct kcpsess_st ps;
    ps.sock_fd = sock_fd;
    ps.dev_fd = dev_fd;
    ps.conv = conv;
    ps.dst = &client;
    ps.dst_len = sizeof(ps.dst);
    ps.kcp=NULL;
    //init_kcp(&ps, 2);

    pthread_t udp2kcpt, dev2kcpt, kcp2devt;

    pthread_create(&udp2kcpt, NULL, udp2kcp, (void *)&ps);
    pthread_detach(udp2kcpt);

    pthread_create(&dev2kcpt, NULL, dev2kcp, (void *)&ps);
    pthread_detach(dev2kcpt);

    pthread_create(&kcp2devt, NULL, kcp2dev, (void *)&ps);
    pthread_detach(kcp2devt);

    update_loop(&ps);
}

static const struct option long_option[]={
   {"port",required_argument,NULL,'p'},
   {"conv",required_argument,NULL,'c'},
   {"algo",required_argument,NULL,'a'},
   {"mode",required_argument,NULL,'m'},
   {"help",no_argument,NULL,'h'},
   {"debug",no_argument,NULL,'d'},
   {NULL,0,NULL,0}
};

void print_help() {
    printf("server [--port=8888] --conv=28445 [--algo=twofish] [--mode=cbc] [--debug]\n");
    exit(0);
}

// server [--algo=twofish] [--mode=cbc]
int main(int argc, char *argv[])
{
    int server_port = SERVER_PORT;
    int conv=-1;
    int opt=0;
    while((opt=getopt_long(argc,argv,"pc:a:m:hd",long_option,NULL))!=-1)
    {
        switch(opt)
        {
            case 0:break;
            case 'p': 
                server_port=atoi(optarg); break;
            case 'c': 
                conv=atoi(optarg); break;
            case 'a': 
                set_mcrypt_algo(optarg); break;
            case 'm': 
                set_mcrypt_mode(optarg); break;
            case 'd': 
                set_debug(); break;
            case 'h': 
                print_help(); break;
        }
    }
    if (conv==-1)
    {
        print_help();
    }
    set_server();
    srand(time(NULL));
    int sock_fd = listening(server_port);
    int dev_fd = init_tap();
    handle(dev_fd, sock_fd, conv);
    logging("server", "close");
    close(sock_fd);
    close(dev_fd);
    return 0;
}