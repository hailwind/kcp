#include "common.h"

static int DEBUG=0;
static int role=0;
static int lz4 = 0;
static int crypt=1;
static char * crypt_algo = MCRYPT_TWOFISH;
static char * crypt_mode = MCRYPT_CBC;
static int mode = 3;

static root_t enabled_log = RB_ROOT;

static char timestr[20];

void logging(char const *name, char const *message, ...)
{
    if (DEBUG==1 || map_get(&enabled_log, name)) {
            time_t now = time(NULL);
            bzero(timestr, 20);
            strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
            printf("[%s] [%d] [%s] ", timestr, (long int)syscall(__NR_gettid), name);
            va_list argptr;
            va_start(argptr, message);
            vfprintf(stdout, message, argptr);
            va_end(argptr);
            printf("\n");
            fflush(stdout);
    }
}

void rlimit() {
  struct rlimit nofile_rlmt;
  nofile_rlmt.rlim_cur = nofile_rlmt.rlim_max = 8192;
  int rv = setrlimit(RLIMIT_NOFILE, &nofile_rlmt);
  if (rv != 0) {
    printf("Failed to set nofile rlimit.\n");
  }

  struct rlimit core_rlmt;
  core_rlmt.rlim_cur = core_rlmt.rlim_max = RLIM_INFINITY;
  rv = setrlimit(RLIMIT_CORE, &core_rlmt);
  if (rv != 0) {
    printf("Failed to set core rlimit.\n");
  }
}

void usr_sig_handler(int signo)
{
  if (signo == SIGUSR2)
    set_debug();
  if (signo == SIGUSR1)
    set_no_debug();
}

void init_logging() {
    char arr[20][15] = ENABLED_LOG;
    int i=0;
    for (i=0;i<20;i++) {
        if (arr[i][0]!='\0') {
            map_put(&enabled_log, arr[i], NULL);
        }
    }
}

void create_pid(char * role, char * ipaddr, int id) {
    int pid = getpid();
    FILE *pid_fd;
    char f_name[256];
    bzero(f_name, 256);
    sprintf(f_name, PID_PATH, role, ipaddr, id);
    if((pid_fd=fopen(f_name,"wt+"))==NULL){
        logging("notice", "create pid file: %s fd: %d failed.", f_name, pid_fd);
        exit(1);
    }
    fprintf(pid_fd, "%d", pid);
    fclose(pid_fd);
}

void delete_pid(char * role, char * ipaddr, int id) {
    char f_name[256];
    bzero(f_name, 256);
    sprintf(f_name, PID_PATH, role, ipaddr, id);
    unlink(f_name);
}

void set_debug(){
    DEBUG=1;
}

void set_no_debug(){
    DEBUG=0;
}

void set_mode(int arq_mode) {
    mode = arq_mode;
}

void set_lz4() {
    lz4 = 1;
}

void set_nocrypt() {
    crypt = 0;
}

void set_mcrypt_algo(char *arg) {
    crypt_algo = arg;
}

void set_mcrypt_mode(char *arg) {
    crypt_mode = arg;
}

void set_server() {
    role = 1;
}

void set_session(void *buf, int len, uint32_t sess_id) {
    char *x = buf+len;
    memcpy(x , &sess_id, 4);
}

uint32_t get_session(void *buf, int len) {
    char *x = buf+len-4;
    uint32_t sess_id;
    memcpy(&sess_id, x, 4);
    return sess_id;
}

uint32_t get_conv(void *buf) {
    uint32_t conv_id;
	memcpy(&conv_id, buf, 4);
    return conv_id;
}

void init_mcrypt(struct mcrypt_st *mcrypt, char *key)
{
    if (crypt) {
        mcrypt->td = mcrypt_module_open(crypt_algo, NULL, crypt_mode, NULL);
        if (mcrypt->td == MCRYPT_FAILED)
        {
            logging("init_mcrypt", "mcrypt_module_open failed algo=%s mode=%s key=%s keysize=%d", crypt_algo, crypt_mode, key, sizeof(key));
            exit(3);
        }
        int iv_size = mcrypt_enc_get_iv_size(mcrypt->td);
        char *IV = malloc(iv_size);
        bzero(IV, iv_size);
        int i=0;
        for (i=0; i< iv_size; i++) {
            IV[i]=rand();
        }
        mcrypt->blocksize = mcrypt_enc_get_block_size(mcrypt->td);
        logging("init_mcrypt", "mcrypt init, key:%s len:%d", key, strlen(key));
        int ret = mcrypt_generic_init(mcrypt->td, key, strlen(key), NULL);
        if (ret<0) {
            mcrypt_perror(ret);
            exit(3);
        }
        mcrypt->enc_state_size = sizeof mcrypt->enc_state;
        mcrypt_enc_get_state(mcrypt->td, mcrypt->enc_state, &mcrypt->enc_state_size);
    }
}

int init_tap(uint32_t conv)
{
    int dev, err;
    char tun_device[] = "/dev/net/tun";
    char devname[20];
    bzero(devname, 20);
    sprintf(devname, "tap%d", conv);
    logging("init_tap", "devname: %s", devname);
    struct ifreq ifr;
    bzero(&ifr, sizeof(struct ifreq));
    if ((dev = open(tun_device, O_RDWR)) < 0)
    {
        logging("init_tap", "open(%s) failed: %s", tun_device, strerror(errno));
        exit(2);
    }
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, strlen(devname));
    if ((err = ioctl(dev, TUNSETIFF, (void *) &ifr)) < 0) {
        logging("init_tap", "ioctl(TUNSETIFF) failed");
        exit(3);
    }
    int flags;
    if (-1 == (flags = fcntl(dev, F_GETFL, 0))) {
        flags = 0;
    }
    fcntl(dev, F_SETFL, flags | O_NONBLOCK);
    logging("init_tap", "init tap dev success. fd: %d", dev);
    return dev;
}

void init_kcp(struct kcpsess_st *ps)
{
    ikcpcb *kcp_ = ikcp_create(ps->conv, ps);
    logging("init_kcp", "ikcp_create, kcps: %p, kcp: %p, buffer: %p", ps, kcp_, kcp_->buffer);
    // 启动快速模式
    // 第二个参数 nodelay-启用以后若干常规加速将启动
    // 第三个参数 interval为内部处理时钟，默认设置为 10ms
    // 第四个参数 resend为快速重传指标，设置为2
    // 第五个参数 为是否禁用常规流控，这里禁止
    switch(mode) {
        case 0:
            ikcp_nodelay(kcp_, M0_MODE); break;
        case 1:
            ikcp_nodelay(kcp_, M1_MODE); break;
        case 2:
            ikcp_nodelay(kcp_, M2_MODE); break;
        case 3:
            ikcp_nodelay(kcp_, M3_MODE); break;
        case 4:
            ikcp_nodelay(kcp_, M4_MODE); break;
        case 5:
            ikcp_nodelay(kcp_, M5_MODE); break;
        case 6:
            ikcp_nodelay(kcp_, M6_MODE); break;
        case 7:
            ikcp_nodelay(kcp_, M7_MODE); break;
        case 8:
            ikcp_nodelay(kcp_, M8_MODE); break;
        default:
            ikcp_nodelay(kcp_, M3_MODE); break;
    }
    ikcp_wndsize(kcp_, SND_WINDOW, RSV_WINDOW);
    ikcp_setmtu(kcp_, MTU);

    kcp_->rx_minrto = RX_MINRTO;
    kcp_->output = udp_output;
    if (ps->kcp) {
        logging("init_kcp", "release kcp: %p, buffer: %p", ps->kcp, ps->kcp->buffer);
        ikcp_release(ps->kcp);
    }
    ps->kcp=kcp_;
    ps->sess_id = 0;
}

void *udp2kcp_client(void *data)
{
    char buff_arr[RCV_BUFF_LEN];
    char *buff = buff_arr;
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    while (1)
    {
        int cnt = recvfrom(kcps->sock_fd, buff, RCV_BUFF_LEN, 0, (struct sockaddr *)&kcps->dst, &(kcps->dst_len));
        if (cnt < 0)
        {
            continue;
        }
        logging("udp2kcp_client", "udp2kcp-1 %ld",timstamp());
        uint32_t sess_id = get_session(buff, cnt);
        cnt-=4;
        if (kcps->sess_id==0) {
            kcps->sess_id = sess_id;
        }
        if (kcps->sess_id!=sess_id || !kcps->kcp) {
            logging("udp2kcp_client", "client reinit_kcp=========== sess_id: %d", sess_id);
            pthread_mutex_lock(&kcps->ikcp_mutex);
            init_kcp((struct kcpsess_st *)data);
            kcps->sess_id = sess_id;
            pthread_mutex_unlock(&kcps->ikcp_mutex);
        }
        logging("udp2kcp_client", "recvfrom udp packet: %d addr: %s sess_id: %d", cnt, inet_ntoa(kcps->dst.sin_addr), kcps->sess_id);
        pthread_mutex_lock(&kcps->ikcp_mutex);
        ikcp_input(kcps->kcp, buff, cnt);
        pthread_mutex_unlock(&kcps->ikcp_mutex);
        logging("udp2kcp_client", "udp2kcp-2 %ld, kcp->state: %d",timstamp(), kcps->kcp->state);
    }
}

void *udp2kcp_server(void *data)
{
    char buff_arr[RCV_BUFF_LEN];
    char *buff = buff_arr;
    struct server_listen_st *server = (struct server_listen_st *)data;
    struct sockaddr_in client;
    bzero(&client, sizeof(struct sockaddr_in));
    socklen_t client_len = sizeof(client);
    struct kcpsess_st * kcps;
    char conv_str[20];
    while (1)
    {
        int cnt = recvfrom(server->sock_fd, buff, RCV_BUFF_LEN, 0, (struct sockaddr *)&client, &client_len);
        if (cnt < (24+4))//24(KCP) 4(SESS)
        {
            continue;
        }
        logging("udp2kcp_server", "udp2kcp-1 %ld",timstamp());
        uint32_t conv = get_conv(buff);
        bzero(conv_str, 20);
        sprintf(conv_str, "%d", conv);
        logging("udp2kcp_server", "udp2kcp-x %d", conv);

        map_t *node = map_get(&server->conn_map->conv_session_map, conv_str);
        if (node && node->val) {
            uint32_t sess_id = get_session(buff, cnt);
            cnt-=4;
            kcps = (struct kcpsess_st * )node->val;
            if (sess_id==0 || !kcps->kcp || kcps->kcp->state==-1) {
                logging("udp2kcp_server", "server reinit_kcp sess_id: %d, kcps: %p, kcp: %p", sess_id, kcps, kcps->kcp);
                pthread_mutex_lock(&kcps->ikcp_mutex);
                memcpy(&kcps->dst, &client, client_len);
                kcps->dst_len = client_len;
                init_kcp(kcps);
                pthread_mutex_unlock(&kcps->ikcp_mutex);
                sess_id = 30000 + rand() % 10000;
                kcps->sess_id = sess_id;
            }
        }else{
            logging("udp2kcp_server", "CONV NOT EXISTS or NOT INIT COMPLETED %s", conv_str);
            continue;
        }
        if (kcps->sock_fd==-1) {
            kcps->sock_fd = server->sock_fd;
        }
        logging("udp2kcp_server", "recvfrom udp packet: %d addr: %s sess_id: %d, kcps: %p, kcp: %p", cnt, inet_ntoa(kcps->dst.sin_addr), kcps->sess_id, kcps, kcps->kcp);
        pthread_mutex_lock(&kcps->ikcp_mutex);
        int ret = ikcp_input(kcps->kcp, buff, cnt);
        pthread_mutex_unlock(&kcps->ikcp_mutex);
        logging("udp2kcp_server", "udp2kcp-2 %ld, result: %d",timstamp(), ret);
    }
}

void *dev2kcp(void *data)
{
    char buff_arr[RCV_BUFF_LEN];
    char *buff = buff_arr;
    char lz4_buff_arr[RCV_BUFF_LEN];
    char *lz4_buff = lz4_buff_arr;
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    struct mcrypt_st mcrypt;
    bzero(&mcrypt, sizeof(struct mcrypt_st));
    init_mcrypt(&mcrypt, kcps->key);
    int sleep_times=0;
    int read_times=0;
    uint16_t total_frms=0;
    uint16_t total_len=16;
    char alive_buff_arr[16] = "  ALIVE";
    char *alive_buff=alive_buff_arr;
    int alive_buff_len=strlen(alive_buff);
    /*
    0,1 int16 总帧数
    2,3 int16 帧1的长度
    4,5 int16 帧2的长度
    6,7 int16 帧3的长度
    8,9 int16 帧4的长度
    10,11 int16 帧5的长度
    12,13 int16 帧6的长度
    14,15 int16 帧7的长度
    */
    while (kcps->dead==0)
    {
        if (!kcps->kcp || kcps->kcp->state==-1) {
            if (role==1) {//server
                isleep(2);
                continue;
            }else{
                logging("warning", "kcp not exists or kcp->state is -1, init kcp.");
                init_kcp(kcps);
            }
        }
        int cnt = read(kcps->dev_fd, buff+total_len, 1514);
        if (cnt>0) {
            logging("dev2kcp", "read data from tap, position: %d, size: %d, read_times: %d", total_len, cnt, read_times);
            total_frms++;
            total_len+=cnt;
            memcpy(buff+total_frms*2, &cnt, 2);
            // uint16_t z;
            // memcpy(&z, buff+total_frms*2, 2);
        }
        if (read_times>=5 || (cnt>0 && cnt<(MTU-24))) {
            memcpy(buff, &total_frms, 2);
            logging("dev2kcp", "dev2kcp-1 %ld",timstamp());
            if (lz4) {
                total_len = LZ4_compress_default(buff, lz4_buff, total_len, RCV_BUFF_LEN);
                buff = lz4_buff_arr;
            }
            if (crypt && mcrypt.blocksize)
            {
                //cnt = ((cnt - 1) / mcrypt.blocksize + 1) * mcrypt.blocksize; // pad to block size
                mcrypt_generic(mcrypt.td, buff, total_len);
                mcrypt_enc_set_state(mcrypt.td, mcrypt.enc_state, mcrypt.enc_state_size);
                if (mcrypt.td==MCRYPT_FAILED) {
                    logging("notice", "crypt failed");
                    continue;
                }
                logging("dev2kcp", "encrypt data: %d", total_len);
            }
            pthread_mutex_lock(&kcps->ikcp_mutex);
            ikcp_send(kcps->kcp, buff, total_len);
            pthread_mutex_unlock(&kcps->ikcp_mutex);
            logging("dev2kcp", "dev2kcp-2 %ld",timstamp());
            total_frms=0;
            total_len=16;
            read_times=0;
            buff = buff_arr;
            continue;
        }
        if (cnt < 0) {
            if (read_times==0) {
                if (sleep_times>100000) {
                    uint16_t zero_frms = 0;
                    memcpy(alive_buff, &zero_frms, 2);
                    if (crypt && mcrypt.blocksize)
                    {
                        //cnt = ((cnt - 1) / mcrypt.blocksize + 1) * mcrypt.blocksize; // pad to block size
                        mcrypt_generic(mcrypt.td, alive_buff, alive_buff_len);
                        mcrypt_enc_set_state(mcrypt.td, mcrypt.enc_state, mcrypt.enc_state_size);
                        if (mcrypt.td==MCRYPT_FAILED) {
                            logging("notice", "crypt failed");
                            continue;
                        }
                    }
                    //logging("warning", "alive_buff: %p", &alive_buff);
                    pthread_mutex_lock(&kcps->ikcp_mutex);
                    ikcp_send(kcps->kcp, alive_buff, alive_buff_len);
                    pthread_mutex_unlock(&kcps->ikcp_mutex);
                    sleep_times=0;
                }
                sleep_times++;
                isleep(0.1);
                continue;
            }else{
                read_times++;
            }
        }else{
            sleep_times=0;
            read_times++;
        }
    }
    mcrypt_generic_deinit(mcrypt.td);
    mcrypt_module_close(mcrypt.td);
    logging("notice", "dev2kcp thread go to dead, conv: %d", kcps->conv);
}

void *kcp2dev(void *data)
{
    char buff_arr[RCV_BUFF_LEN];
    char *buff = buff_arr;
    char lz4_buff_arr[RCV_BUFF_LEN];
    char *lz4_buff = lz4_buff_arr;
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    struct mcrypt_st mcrypt;
    bzero(&mcrypt, sizeof(struct mcrypt_st));
    init_mcrypt(&mcrypt, kcps->key);
    int x = 0;
    uint16_t total_frms=0;
    uint16_t total_len=16;
    while (kcps->dead==0)
    {
        if (!kcps->kcp) {
            isleep(2);
            continue;
        }
        //logging("kcp2dev", "recv-1");
        pthread_mutex_lock(&kcps->ikcp_mutex);
        int cnt = ikcp_recv(kcps->kcp, buff, RCV_BUFF_LEN);
        pthread_mutex_unlock(&kcps->ikcp_mutex);
        //logging("kcp2dev", "recv-2 %d", cnt);
        if (cnt < 16)
        {
            x++;
            if (x > 2000)
            {
                logging("kcp2dev", "recv no data for 2s.");
                x = 0;
            }
            isleep(0.1);
            continue;
        }
        logging("kcp2dev", "kcp2dev-1 %ld",timstamp());
        x = 0;


        logging("kcp2dev", "recv data from kcp: %d", cnt);
        if (crypt && mcrypt.blocksize)
        {
            mdecrypt_generic(mcrypt.td, buff, cnt);
            mcrypt_enc_set_state(mcrypt.td, mcrypt.enc_state, mcrypt.enc_state_size);
            if (mcrypt.td==MCRYPT_FAILED) {
                logging("notice", "decrypt failed");
                continue;
            }
        }
        if (lz4) {
            cnt = LZ4_decompress_safe(buff, lz4_buff, cnt, RCV_BUFF_LEN);
            buff = lz4_buff_arr;
        }
        memcpy(&total_frms, buff, 2);
        if (total_frms<=0 || total_frms>7) {
            logging("kcp2dev", "alive frame or illegal data, r_addr: %s len: %d content: %s", inet_ntoa(kcps->dst.sin_addr), cnt, buff+2);
            //alive OR illegal
            continue;
        }
        uint16_t frm_size;
        int i=0;
        for (i=0;i<total_frms;i++) {
            //logging("kcp2dev", "frm_size: %p, buff: %p x:%p\n", &frm_size, &buff+(i+1)*2);
            memcpy(&frm_size, buff+(i+1)*2, 2);
            int y = write(kcps->dev_fd, buff+total_len, frm_size);
            logging("kcp2dev", "write to dev: idx: %d, position: %d, size: %d, wrote: %d", i, total_len, frm_size, y);
            total_len+=frm_size;
        }
        total_len=16;
        buff = buff_arr;
        logging("kcp2dev", "kcp2dev-2 %ld",timstamp());
    }
    mcrypt_generic_deinit(mcrypt.td);
    mcrypt_module_close(mcrypt.td);
    logging("notice", "kcp2dev thread go to dead, conv: %d", kcps->conv);
}

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{

    logging("udp_output", "udp_output-1 %ld",timstamp());
    logging("udp_output", "length %d", len);
    struct kcpsess_st *kcps = (struct kcpsess_st *)user;
    if (kcps->sock_fd==-1) {
        return 0;
    }
    char *x;
    memcpy(&x, &buf, sizeof(buf)); // const 指针不能直接赋值给另外一个可变指针，所以用拷贝指针地址的方法创建一个新的临时指针．
    set_session(x, len, kcps->sess_id);
    len += 4;
    int cnt = sendto(kcps->sock_fd, buf, len, 0, (struct sockaddr *)&kcps->dst, kcps->dst_len);
    if (cnt < 0)
    {
        logging("udp_output", "addr: %s port: %d", inet_ntoa(kcps->dst.sin_addr), ntohs(kcps->dst.sin_port));
        logging("udp_output", "udp send failed");
    }
    logging("udp_output", "kcp.state: %d sess_id: %d", kcp->state, kcps->sess_id);
    logging("udp_output", "udp_output-2 %ld",timstamp());
    return 0;
}

void * kcpupdate_server(void *data)
{
    struct connection_map_st *conn_m = (struct connection_map_st *)data;
    const char *key;
    struct kcpsess_st *kcps;
    while (1)
    {
        map_t *node;
        for (node = map_first(&conn_m->conv_session_map); node; node=map_next(&(node->node))) {
            //logging("kcpupdate_server", "update conv: %s", node->key);
            kcps=(struct kcpsess_st *) (node->val);
            if (kcps && kcps->kcp) {
                //logging("kcpupdate_server", "ikcp_update,kcps: %p kcp: %p, buffer: %p",kcps, kcps->kcp, kcps->kcp->buffer);
                pthread_mutex_lock(&kcps->ikcp_mutex);
                ikcp_update(kcps->kcp, iclock());
                pthread_mutex_unlock(&kcps->ikcp_mutex);
            }
        }
        isleep(0.1);
    }
}

void kcpupdate_client(struct kcpsess_st *kcps)
{
    while (1)
    {
        if (kcps->kcp) {
            uint32_t current = iclock();
            pthread_mutex_lock(&kcps->ikcp_mutex);
            uint32_t next = ikcp_check(kcps->kcp, current);
            pthread_mutex_unlock(&kcps->ikcp_mutex);
            uint32_t diff = next-current;
            if (diff>0) {
                isleep(0.1);
            }
            pthread_mutex_lock(&kcps->ikcp_mutex);
            ikcp_update(kcps->kcp, iclock());
            pthread_mutex_unlock(&kcps->ikcp_mutex);
        }else{
            isleep(2);
        }
    }

}