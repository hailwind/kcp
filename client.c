#include "common.h"
#include <getopt.h>

void handle(int dev_fd, int sock_fd, int conv, struct sockaddr_in *dst)
{
    struct kcpsess_st ps;
    ps.sock_fd = sock_fd;
    ps.dev_fd = dev_fd;
    ps.conv = conv;
    ps.dst = dst;
    ps.dst_len = sizeof(dst);
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

int learn=0;
static const struct option long_option[]={
   {"server",required_argument,NULL,'s'},
   {"port",required_argument,NULL,'p'},
   {"conv",required_argument,NULL,'c'},
   {"no-crypt",no_argument,NULL,'C'},
   {"crypt-algo",required_argument,NULL,'A'},
   {"crypt-mode",required_argument,NULL,'M'},
   {"mode",required_argument,NULL,'m'}, 
   {"debug",no_argument,NULL,'d'},
   {"help",no_argument,NULL,'h'},
   {NULL,0,NULL,0}
};

void print_help() {
    printf("client --server=192.168.1.1 [--port=8888] --conv=28445 [--no-crypt] [--crypt-algo=twofish] [--crypt-mode=cbc] [--mode=4] [--debug]\n");
    exit(0);
}

//client --server 192.168.1.1 [--algo=twofish] [--mode=cbc]
int main(int argc, char *argv[])
{
    char * server_addr;
    int server_port = SERVER_PORT;
    int conv=-1;
    int opt=0;
    while((opt=getopt_long(argc,argv,"s:p:c:h",long_option,NULL))!=-1)
    {
        switch(opt)
        {
            case 0: break;
            case 's': 
                server_addr=optarg; break;
            case 'p': 
                server_port=atoi(optarg); break;
            case 'c': 
                conv=atoi(optarg); break;
            case 'C':
                set_nocrypt(); break;
            case 'A': 
                set_mcrypt_algo(optarg); break;
            case 'M': 
                set_mcrypt_mode(optarg); break;
            case 'm': 
                set_mode(atoi(optarg)); break;
            case 'd': 
                set_debug(); break;
            case 'h': 
                print_help(); break;
        }
    }
    
    if (!server_addr || conv==-1)
    {
        print_help();
    }
    int dev_fd = init_tap();
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        logging("client", "create socket fail!");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in ser_addr;
    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(server_addr);
    ser_addr.sin_port = htons(server_port);
    handle(dev_fd, sock_fd, conv, &ser_addr);
    logging("client", "close");
    close(sock_fd);
    close(dev_fd);

    return 0;
}