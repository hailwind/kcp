#include <getopt.h>
#include "common.h"

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

void manage_threads(struct connection_map_st *conn_m) {
    const char *key;
    struct kcpsess_st *kcps;
    while (1)
    {
        map_iter_t iter = map_iter(&conn_m->allowed_conv);
        while ((key = map_next(&conn_m->allowed_conv, &iter))) {
            void *v = map_get(&conn_m->conv_session_map, key);
            if (v) {
                kcps = (struct kcpsess_st *)v;
                if (kcps->dev2kcpt==0) {
                    pthread_create(&kcps->dev2kcpt, NULL, dev2kcp, (void *)kcps);
                    pthread_detach(kcps->dev2kcpt);
                    logging("manage_threads", "create dev2kcp thread: %d", kcps->dev2kcpt);
                }
                if (kcps->kcp2devt==0) {
                    pthread_create(&kcps->kcp2devt, NULL, kcp2dev, (void *)kcps);
                    pthread_detach(kcps->kcp2devt);
                    logging("manage_threads", "create kcp2dev thread: %d", kcps->kcp2devt);
                }
            }
        }
        isleep(5000);
    }
}

void handle(int sock_fd)
{
    struct connection_map_st conn_map;
    map_init(&conn_map.allowed_conv);
    map_set(&conn_map.allowed_conv, DEFAULT_ALLOWED_CONV, 1);
    map_init(&conn_map.conv_session_map);

    conn_map.sock_fd = sock_fd;
    struct sockaddr_in client;
    pthread_t udp2kcpt, updateloopt;

    pthread_create(&udp2kcpt, NULL, udp2kcp_server, (void *)&conn_map);
    pthread_detach(udp2kcpt);
    logging("handle", "create udp2kcp_server thread: %d", udp2kcpt);

    pthread_create(&updateloopt, NULL, kcpupdate_server, (void *)&conn_map);
    pthread_detach(updateloopt);
    logging("handle", "create kcpupdate_server thread: %d", updateloopt);

    manage_threads(&conn_map);
}

static const struct option long_option[]={
   {"bind",required_argument,NULL,'b'},
   {"port",required_argument,NULL,'p'},
   {"no-crypt",no_argument,NULL,'C'},
   {"crypt-algo",required_argument,NULL,'A'},
   {"crypt-mode",required_argument,NULL,'M'},
   {"mode",required_argument,NULL,'m'}, 
   {"debug",no_argument,NULL,'d'},
   {"help",no_argument,NULL,'h'},
   {NULL,0,NULL,0}
};

void print_help() {
    printf("server [--bind=0.0.0.0] [--port=8888] [--no-crypt] [--crypt-algo=twofish] [--crypt-mode=cbc] [--mode=3] [--debug]\n");
    exit(0);
}

// server [--algo=twofish] [--mode=cbc]
int main(int argc, char *argv[])
{
    init_logging();
    char *bind_addr = "0.0.0.0";
    int server_port = SERVER_PORT;
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
            case 'd': 
                set_debug(); break;
            case 'h': 
                print_help(); break;
        }
    }
    set_server();
    srand(time(NULL));
    int sock_fd = listening(bind_addr, server_port);
    handle(sock_fd);
    logging("server", "close");
    close(sock_fd);
    return 0;
}