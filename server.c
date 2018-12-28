#include <getopt.h>
#include "common.h"

#define FIFO "/var/run/fifo"

void print_help() {
    printf("\
//start a server process.\n\
server [--bind=0.0.0.0] [--port=8888] [--mode=3] [--with-lz4] [--no-crypt]  [--crypt-algo=twofish] [--crypt-mode=cbc] [--debug]\n\
//add a conv to a server, identify the server by port. \n\
server [--port=8888] --add-conv=38837 --crypt-key=0123456789012345678901234567890\n\
//del a conv from a server, identify the server by port. \n\
server [--port=8888] --del-conv=38837\n");
    exit(0);
}

static int listening(char *bind_addr, int port)
{
    struct sockaddr_in server;
    bzero(&server, sizeof(server));
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0)
    {
        logging("listening", "create socket fail!");
        exit(EXIT_FAILURE);
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(bind_addr);
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

struct kcpsess_st * init_kcpsess(struct connection_map_st *conn_map, 
                                uint32_t conv, char *key)
{
    int dev_fd = init_tap(conv);
    struct kcpsess_st *ps = (struct kcpsess_st *)malloc(sizeof(struct kcpsess_st));
    bzero(ps, sizeof(struct kcpsess_st));
    ps->sock_fd = -1;
    ps->dev_fd = dev_fd;
    ps->conv = conv;
    ps->kcp = NULL;
    ps->sess_id = 0;
    ps->dev2kcpt = 0;
    ps->kcp2devt = 0;
    ps->dead = 0;
    strncpy(ps->key, key, strlen(key));
    pthread_mutex_t ikcp_mutex = PTHREAD_MUTEX_INITIALIZER;
    ps->ikcp_mutex = ikcp_mutex;
    logging("init_kcpsess","kcps: %p", ps);
    return ps;
}

void set_conv_dead(struct connection_map_st *conn_map, char *conv) {
    map_t *node;
    node = map_get(&conn_map->conv_session_map, conv);
    if (node && node->val) {
        struct kcpsess_st *kcps = node->val;
        kcps->dead = 1;
        sleep(1);
        int ret;
        ret = pthread_cancel(kcps->dev2kcpt);
        logging("notice", "cancel dev2kcpt ret: %d\n", ret);
        ret = pthread_cancel(kcps->kcp2devt);
        logging("notice", "cancel kcp2devt ret: %d\n", ret);
        sleep(1);
        if (kcps->dev_fd>0) close(kcps->dev_fd);
        if (kcps->kcp) ikcp_release(kcps->kcp);
        map_delete(&conn_map->conv_session_map, node);
//        free(kcps);
    }
}

int open_fifo(int port, char rw) {
    int fifo_fd;
    char fifo_file[50];
    bzero(&fifo_file, 50);
    sprintf(fifo_file, "%s.%d", FIFO, port);
    /*
    0 exists
    2 write
    4 read
    */
    if(mkfifo(fifo_file, 0666)) {
        perror("Mkfifo error");  
    }
    if (rw=='R') {
        fifo_fd=open(fifo_file, O_RDONLY|O_NONBLOCK);
    }else if (rw=='W') {
        fifo_fd=open(fifo_file, O_WRONLY);
    }
    logging("notice", "open fifo: %s, fd: %d", fifo_file, fifo_fd);
    return fifo_fd;
}


void start_thread(struct kcpsess_st *kcps) {
    if (kcps->dev2kcpt==0) {
        pthread_create(&kcps->dev2kcpt, NULL, dev2kcp, (void *)kcps);
        pthread_detach(kcps->dev2kcpt);
        logging("notice", "create dev2kcp thread: %ld", kcps->dev2kcpt);
    }
    if (kcps->kcp2devt==0) {
        pthread_create(&kcps->kcp2devt, NULL, kcp2dev, (void *)kcps);
        pthread_detach(kcps->kcp2devt);
        logging("notice", "create kcp2dev thread: %ld", kcps->kcp2devt);
    }
}

void read_fifo(struct connection_map_st *conn_map) {
    if (conn_map->fifo_fd>=0) {
        char buf[128];
        bzero(&buf, 128);
        int count=read(conn_map->fifo_fd, buf, 127);
        if (count>7) {
            logging("read_fifo", "read fifo: %s, %d bytes", buf, count);
            char *conv;
            char *key;
            int tmp=0;
            conv = (void *)&buf+3;
            int i=3;
            for (i=3;i<count;i++) {
                if (buf[i]=='&') {
                    buf[i]='\0';
                    key = (void *)&buf + i +1;
                }
                if (buf[i]=='\n') {
                    buf[i]='\0';
                    break;
                }
            }
            if (strncmp("ADD", buf, 3)==0) {
                map_t *node = map_get(&conn_map->conv_session_map, conv);
                if (!node) {
                    struct kcpsess_st *kcps = init_kcpsess(conn_map, atoi(conv), key);
                    start_thread(kcps);
                    map_put(&conn_map->conv_session_map, conv, kcps);
                    logging("notice", "server init_kcpsess conv: %s key: %s kcps: %p", conv, key, kcps);
                }else{
                    logging("notice", "conv %s exists.", conv);
                }
            }else if(strncmp("DEL", buf, 3)==0) {
                set_conv_dead(conn_map, conv);
            }
        }else{
            logging("read_fifo", "read fifo: %d bytes", count);
        }
    }
    logging("read_fifo", "exit read_fifo");
}


void send_fifo(int fifo_fd, char *cmd, char *conv, char *key) {
    char buf[128];
    bzero(&buf, 128);
    strcat(buf, cmd);
    strcat(buf, conv);
    if(key && strlen(key)>=16 && strlen(key)<=32) {
        strcat(buf, "&");
        strcat(buf, key);
    }else{
        logging("notice", "no key input or key too long, the length must be between 16 and 32");
        print_help();
        exit(1);
    }
    strcat(buf, "\n");
  
    int cnt = write(fifo_fd, buf, strlen(buf));
    logging("notice", "sent %d bytes: %s", cnt, buf);
}

void wait_conv(struct connection_map_st *conn_m) {
    while (1)
    {
        read_fifo(conn_m);
        sleep(1);
    }
}

void handle(struct server_listen_st *server)
{
    pthread_t udp2kcpt;
    pthread_create(&udp2kcpt, NULL, udp2kcp_server, (void *)server);
    pthread_detach(udp2kcpt);
    logging("handle", "create udp2kcp_server thread: %ld", udp2kcpt);
}

void exit_sig_signal(int signo) {
    if (signo==SIGINT || signo==SIGQUIT || signo == SIGTERM) {
        logging("notice", "exit.");
        exit(0);
    }
}

static const struct option long_option[]={
   {"bind",required_argument,NULL,'b'},
   {"port",required_argument,NULL,'p'},
   {"with-lz4",no_argument,NULL,'Z'},
   {"no-crypt",no_argument,NULL,'C'},
   {"crypt-key",required_argument,NULL,'k'},
   {"crypt-algo",required_argument,NULL,'A'},
   {"crypt-mode",required_argument,NULL,'M'},
   {"mode",required_argument,NULL,'m'},
   {"del",required_argument,NULL,'X'},
   {"add",required_argument,NULL,'Y'},
   {"del-conv",required_argument,NULL,'X'},
   {"add-conv",required_argument,NULL,'Y'},
   {"debug",no_argument,NULL,'d'},
   {"help",no_argument,NULL,'h'},
   {NULL,0,NULL,0}
};

// server [--algo=twofish] [--mode=cbc]
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
    char all_addr[20]="0.0.0.0";
    char *bind_addr = all_addr;
    int server_port = SERVER_PORT;
    char *key = NULL;
    char *conv = NULL;
    char *cmd = NULL;
    int opt=0;
    while((opt=getopt_long(argc,argv,"p:c:h",long_option,NULL))!=-1)
    {
        switch(opt)
        {
            case 0:break;
            case 'b': 
                bind_addr=optarg; break;
            case 'p': 
                server_port=atoi(optarg); break;
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
            case 'X':
                cmd = "DEL";
                conv = optarg;
                break;
            case 'Y':
                cmd = "ADD";
                conv = optarg;
                break;
            case 'd': 
                set_debug(); break;
            case 'h': 
                print_help(); break;
        }
    }
    if(cmd && conv) {
        send_fifo(open_fifo(server_port, 'W'), cmd, conv, key);
        exit(0);
    }
    set_server();
    srand(time(NULL));
    create_pid("server", server_port);
    struct connection_map_st conn_map;
    bzero(&conn_map, sizeof(struct connection_map_st));
    conn_map.conv_session_map = RB_ROOT;
    #ifdef DEFAULT_ALLOWED_CONV
    map_put(&conn_map.conv_session_map, DEFAULT_ALLOWED_CONV, NULL);
    #endif

    char *mPtr = NULL;
    mPtr = strtok(bind_addr, ",");
    while (mPtr != NULL)
    {
        int sock_fd = listening(mPtr, server_port);
        struct server_listen_st *server = malloc(sizeof(struct server_listen_st));
        bzero(server, sizeof(struct server_listen_st));
        server->sock_fd = sock_fd;
        server->conn_map = &conn_map;
        handle(server);
        mPtr = strtok(NULL, ",");
    }

    pthread_t updateloopt;
    pthread_create(&updateloopt, NULL, kcpupdate_server, (void *)&conn_map);
    pthread_detach(updateloopt);
    logging("notice", "create kcpupdate_server thread: %ld", updateloopt);

    int fifo_fd = open_fifo(server_port, 'R');
    conn_map.fifo_fd = fifo_fd;
    wait_conv(&conn_map);
}