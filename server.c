#include <getopt.h>
#include "common.h"

#define FIFO "/var/run/fifo"

static int listening(char *bind_addr, int port)
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
                                uint32_t conv)
{
    int dev_fd = init_tap(conv);
    struct kcpsess_st *ps = (struct kcpsess_st *)malloc(sizeof(struct kcpsess_st));
    ps->sock_fd = conn_map->sock_fd;
    ps->dev_fd = dev_fd;
    ps->conv = conv;
    ps->kcp = NULL;
    ps->sess_id = 0;
    ps->dev2kcpt = 0;
    ps->kcp2devt = 0;
    ps->dead = 0;
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
        free(kcps);
    }
}


int open_fifo(int port, char rw) {
    int fifo_fd;
    char fifo_file[50];
    memset(&fifo_file, '\0', 50);
    sprintf(fifo_file, "%s.%d", FIFO, port);
    //printf("%s\n", fifo_file);
    /*
    0 exists
    2 write
    4 read
    */
    if (access(fifo_file, 0)==-1) {
        if(mkfifo(fifo_file, 666)) {
            perror("Mkfifo error");
        }
        chmod(fifo_file, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    }
    if (rw=='R') {
        fifo_fd=open(fifo_file, O_RDONLY|O_NONBLOCK);
    }
    if (rw=='W') {
        fifo_fd=open(fifo_file, O_WRONLY|O_NONBLOCK);
    }
    return fifo_fd;
}

void send_fifo(int fifo_fd, char *cmd, char *conv) {
    char buf[128];
    sprintf(buf, "%s%s\n", cmd, conv);
    int cnt = write(fifo_fd, buf, strlen(buf));
    logging("notice", "sent %d bytes: %s", cnt, buf);
    exit(0);
}

void read_fifo(struct connection_map_st *conn_map) {
    //logging("read_fifo", "invoke read_fifo");
    if (conn_map->fifo_fd>=0) {
        char buf[128];
        memset(buf, '\0', 128);
        int count=read(conn_map->fifo_fd, buf, 127);
        if (count>7) {
            for (int i=3;i<count;i++) {
                if (buf[i]=='\n' || buf[i]=='\0') {
                    buf[i]='\0';
                    break;
                }
            }
            logging("read_fifo", "read fifo: %s, %d bytes", buf, count);
            char *conv = buf+3;
            if (strncmp("ADD", buf, 3)==0) {
                map_t *node = map_get(&conn_map->conv_session_map, conv);
                if (!node) {
                    map_put(&conn_map->conv_session_map, conv, NULL);
                }else{
                    logging("read_fifo", "conv %s exists.", conv);
                }
            }else if(strncmp("DEL", buf, 3)==0) {
                set_conv_dead(conn_map, conv);
            }
        }
    }
    //logging("read_fifo", "exit read_fifo");
}

void manage_conn(struct connection_map_st *conn_m) {
    while (1)
    {
        read_fifo(conn_m);
        map_t *node;
        for (node = map_first(&conn_m->conv_session_map); node; node=map_next(&(node->node))) {
            //logging("manage_conn", "process: %s, val: %p", node->key, node->val);
            if (!node->val) {
                struct kcpsess_st *kcps = init_kcpsess(conn_m, atoi(node->key));
                logging("manage_conn", "server init_kcpsess conv: %s kcps: %p", node->key, kcps);
                node->val = kcps;
                //map_put(&conn_m->conv_session_map, node->key, kcps);
                if (kcps->dev2kcpt==0) {
                    pthread_create(&kcps->dev2kcpt, NULL, dev2kcp, (void *)kcps);
                    pthread_detach(kcps->dev2kcpt);
                    logging("manage_conn", "create dev2kcp thread: %ld", kcps->dev2kcpt);
                }
                if (kcps->kcp2devt==0) {
                    pthread_create(&kcps->kcp2devt, NULL, kcp2dev, (void *)kcps);
                    pthread_detach(kcps->kcp2devt);
                    logging("manage_conn", "create kcp2dev thread: %ld", kcps->kcp2devt);
                }
            }
        }
        isleep(5000);
    }
}

void handle(int sock_fd, int fifo_fd)
{
    struct connection_map_st conn_map;
    conn_map.sock_fd = sock_fd;
    conn_map.fifo_fd = fifo_fd;
    conn_map.conv_session_map = RB_ROOT;

    #ifdef DEFAULT_ALLOWED_CONV
    map_put(&conn_map.conv_session_map, DEFAULT_ALLOWED_CONV, NULL);
    #endif

    pthread_t udp2kcpt, updateloopt;

    pthread_create(&udp2kcpt, NULL, udp2kcp_server, (void *)&conn_map);
    pthread_detach(udp2kcpt);
    logging("handle", "create udp2kcp_server thread: %ld", udp2kcpt);

    pthread_create(&updateloopt, NULL, kcpupdate_server, (void *)&conn_map);
    pthread_detach(updateloopt);
    logging("handle", "create kcpupdate_server thread: %ld", updateloopt);

    manage_conn(&conn_map);
}

static const struct option long_option[]={
   {"bind",required_argument,NULL,'b'},
   {"port",required_argument,NULL,'p'},
   {"no-crypt",no_argument,NULL,'C'},
   {"crypt-algo",required_argument,NULL,'A'},
   {"crypt-mode",required_argument,NULL,'M'},
   {"mode",required_argument,NULL,'m'},
   {"del",required_argument,NULL,'X'},
   {"add",required_argument,NULL,'Y'},
   {"debug",no_argument,NULL,'d'},
   {"help",no_argument,NULL,'h'},
   {NULL,0,NULL,0}
};


void print_help() {
    printf("server [--bind=0.0.0.0] [--port=8888] [--no-crypt] [--crypt-algo=twofish] [--crypt-mode=cbc] [--mode=3] [--add=38837] [--del=38837] [--debug]\n");
    exit(0);
}

// server [--algo=twofish] [--mode=cbc]
int main(int argc, char *argv[])
{
    init_logging();
    char *bind_addr = "0.0.0.0";
    int server_port = SERVER_PORT;
    char *cmd = "ADD";
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
            case 'C':
                set_nocrypt(); break;
            case 'A': 
                set_mcrypt_algo(optarg); break;
            case 'M': 
                set_mcrypt_mode(optarg); break;
            case 'm': 
                set_mode(atoi(optarg)); break;
            case 'X': 
                send_fifo(open_fifo(server_port, 'W'), "DEL", optarg);
                break;
            case 'Y': 
                send_fifo(open_fifo(server_port, 'W'), "ADD", optarg);
                break;
            case 'd': 
                set_debug(); break;
            case 'h': 
                print_help(); break;
        }
    }
    set_server();
    srand(time(NULL));
    int sock_fd = listening(bind_addr, server_port);
    int fifo_fd = open_fifo(server_port, 'R');
    handle(sock_fd, fifo_fd);
    logging("server", "close");
    close(sock_fd);
    return 0;
}