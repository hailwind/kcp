#include "common.h"
#include <getopt.h>

char * server_addr;
int server_port = SERVER_PORT;
int conv=0;
int sock_fd;
int dev_fd;

void handle(int dev_fd, int sock_fd, int conv, struct sockaddr_in *dst, char *key)
{
    struct kcpsess_st *ps = (struct kcpsess_st *)malloc(sizeof(struct kcpsess_st));
    bzero(ps, sizeof(struct kcpsess_st));
    ps->sock_fd = sock_fd;
    ps->dev_fd = dev_fd;
    ps->conv = conv;
    ps->dst = *dst;
    ps->dst_len = sizeof(ps->dst);
    ps->kcp = NULL;
    ps->sess_id = 0;
    ps->dead = 0;
    strncpy(ps->key, key, strlen(key));
    pthread_mutex_t ikcp_mutex = PTHREAD_MUTEX_INITIALIZER;
    ps->ikcp_mutex = ikcp_mutex;

    sigaddset(&ps->toudp_sigset, SIGRTMIN+1);
    sigaddset(&ps->todev_sigset, SIGRTMIN);

    pthread_t udp2kcpt;
    pthread_create(&udp2kcpt, NULL, udp2kcp_client, (void *)ps);
    pthread_detach(udp2kcpt);

    pthread_create(&ps->dev2kcpt, NULL, dev2kcp, (void *)ps);
    pthread_detach(ps->dev2kcpt);

    pthread_create(&ps->kcp2devt, NULL, kcp2dev, (void *)ps);
    pthread_detach(ps->kcp2devt);

    pthread_create(&ps->updatet, NULL, kcpupdate, (void *)ps);
    pthread_detach(ps->updatet);
}

void exit_sig_signal(int signo) {
    if (signo==SIGINT || signo==SIGQUIT || signo == SIGTERM) {
        delete_pid("client", server_addr, server_port);
        close(sock_fd);
        close(dev_fd);
        logging("notice", "exit.");
        exit(0);
    }
}

int learn=0;
static const struct option long_option[]={
   {"server",required_argument,NULL,'s'},
   {"port",required_argument,NULL,'p'},
   {"conv",required_argument,NULL,'c'},
   {"with-lz4",no_argument,NULL,'Z'},
   {"no-crypt",no_argument,NULL,'C'},
   {"crypt-key",required_argument,NULL,'k'},
   {"crypt-algo",required_argument,NULL,'A'},
   {"crypt-mode",required_argument,NULL,'M'},
   {"mode",required_argument,NULL,'m'}, 
   {"debug",no_argument,NULL,'d'},
   {"help",no_argument,NULL,'h'},
   {NULL,0,NULL,0}
};

void print_help() {
    printf("client --server=192.168.1.1 [--port=8888] --conv=28445 [--with-lz4] [--no-crypt] --crypt-key=0123456789012345678901234567890 [--crypt-algo=twofish] [--crypt-mode=cbc] [--mode=3] [--debug]\n");
    exit(0);
}

//client --server 192.168.1.1 [--algo=twofish] [--mode=cbc]
int main(int argc, char *argv[])
{
    init_logging();
    rlimit();
    if (signal(SIGUSR1, usr_sig_handler) == SIG_ERR \
        || signal(SIGUSR2, usr_sig_handler) == SIG_ERR ) {
        logging("warning", "Failed to register USR signal");
    }
    if (signal(SIGINT, exit_sig_signal) == SIG_ERR \
        || signal(SIGQUIT, exit_sig_signal) == SIG_ERR \
        || signal(SIGTERM, exit_sig_signal) == SIG_ERR ) {
        logging("warning", "Failed to register exit signal");
    }
    char * key;
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
            case 'Z':
                set_lz4(); break;
            case 'C':
                set_nocrypt(); break;
            case 'k':
                key=optarg; break;
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
    if (!server_addr || conv==0 || !key || strlen(key)<16) {
        print_help();
    }
    if(!key && strlen(key)<16 && strlen(key)>32) {
        logging("notice", "no key input or key too long, the length must be between 16 and 32");
        exit(1);
    }
    create_pid("client", server_addr, server_port);
    dev_fd = init_tap(conv);
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        logging("client", "create socket fail!");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in ser_addr;
    bzero(&ser_addr, sizeof(struct sockaddr_in));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(server_addr);
    ser_addr.sin_port = htons(server_port);
    logging("client", "open server_addr: %s, server_port: %d, key: %s, keyp: %p", server_addr, server_port, key, &key);
    handle(dev_fd, sock_fd, conv, &ser_addr, key);
    while(1) {
        sleep(10);
    }
    logging("client", "close.");
    return 0;
}