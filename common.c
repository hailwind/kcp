#include "common.h"

pthread_mutex_t ikcp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sess_id_mutex = PTHREAD_MUTEX_INITIALIZER;

static int DEBUG=0;
static int role=0;
static char * algo = MCRYPT_TWOFISH;
static char * mode = MCRYPT_CBC;

void logging(char const *name, char const *message, ...)
{
    if (DEBUG==1) {
        time_t now = time(NULL);
        char timestr[20];
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

void set_debug(){
    DEBUG=1;
}

void set_mcrypt_algo(char *arg) {
    algo = arg;
}

void set_mcrypt_mode(char *arg) {
    mode = arg;
}

void set_server() {
    role = 1;
}

int init_tap(void)
{
    int dev;
    char tun_device[] = "/dev/net/tun";
    char dev_name[] = "tap%d";
    int tuntap_flag = IFF_TAP;
    struct ifreq ifr;
    if ((dev = open(tun_device, O_RDWR)) < 0)
    {
        logging("init_tap", "open(%s) failed: %s", tun_device, strerror(errno));
        exit(2);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tuntap_flag | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    if (ioctl(dev, TUNSETIFF, (void *)&ifr) < 0)
    {
        logging("init_tap", "ioctl(TUNSETIFF) failed");
        exit(3);
    }
    logging("init_tap", "init tap dev success. fd: %d", dev);
    return dev;
};

void init_kcp(struct kcpsess_st *ps, int mode)
{
    ikcpcb *kcp_ = ikcp_create(ps->conv, ps);
    if (mode == 0)
    {
        // 默认模式
        ikcp_nodelay(kcp_, DEFAULT_MODE);
    }
    else if (mode == 1)
    {
        // 普通模式，关闭流控等
        ikcp_nodelay(kcp_, NORMAL_MODE);
    }
    else
    {
        // 启动快速模式
        // 第二个参数 nodelay-启用以后若干常规加速将启动
        // 第三个参数 interval为内部处理时钟，默认设置为 10ms
        // 第四个参数 resend为快速重传指标，设置为2
        // 第五个参数 为是否禁用常规流控，这里禁止
        ikcp_nodelay(kcp_, FAST_MODE);
        //kcp_->rx_minrto = 10;
        kcp_->fastresend = 1;
    }

    ikcp_wndsize(kcp_, SND_WINDOW, RSV_WINDOW);
    ikcp_setmtu(kcp_, MTU);

    kcp_->rx_minrto = RX_MINRTO;
    kcp_->output = udp_output;
    if (ps->kcp) {
        ikcp_release(ps->kcp);
    }
    ps->kcp = kcp_;
    ps->sess_id = 0;
}

void init_mcrypt(struct mcrypt_st *mcrypt)
{
    char key[] = KEY;
    mcrypt->td = mcrypt_module_open(algo, NULL, mode, NULL);
    if (mcrypt->td == MCRYPT_FAILED)
    {
        logging("init_mcrypt", "mcrypt_module_open failed algo=%s mode=%s keysize=%d", algo, mode, sizeof(key));
        exit(3);
    }
    mcrypt->blocksize = mcrypt_enc_get_block_size(mcrypt->td);
    mcrypt_generic_init(mcrypt->td, key, sizeof(key), NULL);
    mcrypt->enc_state_size = sizeof mcrypt->enc_state;
    mcrypt_enc_get_state(mcrypt->td, mcrypt->enc_state, &mcrypt->enc_state_size);
};

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

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    logging("udp_output", "length %d", len);
    struct kcpsess_st *kcps = (struct kcpsess_st *)user;
    
    pthread_mutex_lock(&sess_id_mutex);
    char *x;
    memcpy(&x, &buf, sizeof(buf));
    set_session(x, len, kcps->sess_id);
    len += 4;
    pthread_mutex_unlock(&sess_id_mutex);

    int cnt = sendto(kcps->sock_fd, buf, len, 0, (struct sockaddr *)kcps->dst, sizeof(*kcps->dst));
    if (cnt < 0)
    {
        logging("udp_output", "addr: %s port: %d", inet_ntoa(kcps->dst->sin_addr), ntohs(kcps->dst->sin_port));
        logging("udp_output", "udp send failed");
    }
    logging("udp_output", "kcp.state: %d sess_id: %d", kcp->state, kcps->sess_id);
    return 0;
};

void *udp2kcp(void *data)
{
    char buff[RCV_BUFF_LEN];
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    while (1)
    {
        int cnt = recvfrom(kcps->sock_fd, &buff, RCV_BUFF_LEN, 0, (struct sockaddr *)kcps->dst, &(kcps->dst_len));
        if (cnt < 0)
        {
            continue;
        }
        uint32_t sess_id = get_session(&buff, cnt);
        cnt-=4;
        pthread_mutex_lock(&sess_id_mutex);
        if (role==1) {//server
            if (!kcps->kcp || sess_id==0)
            {
                logging("udp2kcp", "server reinit_kcp===========");
                init_kcp((struct kcpsess_st *)data, 2);
                sess_id = 30000 + rand() % 10000;
                kcps->sess_id = sess_id;
            }
        }else{
            if (kcps->sess_id==0) {
                kcps->sess_id = sess_id;
            }
            if (kcps->sess_id!=sess_id) {
                logging("udp2kcp", "client reinit_kcp===========");
                kcps->sess_id = sess_id;
                init_kcp((struct kcpsess_st *)data, 2);
            }
        }
        pthread_mutex_unlock(&sess_id_mutex);

        logging("udp2kcp", "recvfrom udp packet: %d addr: %s sess_id: %d", cnt, inet_ntoa(kcps->dst->sin_addr), kcps->sess_id);
        pthread_mutex_lock(&ikcp_mutex);
        ikcp_input(kcps->kcp, buff, cnt);
        pthread_mutex_unlock(&ikcp_mutex);
    }
}

void *dev2kcp(void *data)
{
    char buff[RCV_BUFF_LEN];
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    struct mcrypt_st mcrypt;
    init_mcrypt(&mcrypt);
    while (1)
    {
        int cnt = read(kcps->dev_fd, (void *)&buff, RCV_BUFF_LEN);
        if (!kcps->kcp) {
            if (role==1) {//server
                continue;
            }else{
                init_kcp((struct kcpsess_st *)data, 2);
            }
        }
        logging("dev2kcp", "read data from tap: %d", cnt);
        if (cnt < 0)
        {
            continue;
        }
        if (mcrypt.blocksize)
        {
            cnt = ((cnt - 1) / mcrypt.blocksize + 1) * mcrypt.blocksize; // pad to block size
            mcrypt_generic(mcrypt.td, (void *)&buff, cnt);
            mcrypt_enc_set_state(mcrypt.td, mcrypt.enc_state, mcrypt.enc_state_size);
        }
        pthread_mutex_lock(&ikcp_mutex);
        ikcp_send(kcps->kcp, buff, cnt);
        pthread_mutex_unlock(&ikcp_mutex);
    }
}

void *kcp2dev(void *data)
{
    char buff[RCV_BUFF_LEN];
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    struct mcrypt_st mcrypt;
    init_mcrypt(&mcrypt);
    int x = 0;
    while (1)
    {
        while (1)
        {
            if (!kcps->kcp) {
                continue;
            }
            pthread_mutex_lock(&ikcp_mutex);
            int cnt = ikcp_recv(kcps->kcp, buff, RCV_BUFF_LEN);
            pthread_mutex_unlock(&ikcp_mutex);
            if (cnt < 0)
            {
                x++;
                if (x > 2000)
                {
                    logging("kcp2dev", "recv no data for 2s.");
                    x = 0;
                }
                break;
            }
            x = 0;
            logging("kcp2dev", "recv data from kcp: %d", cnt);
            if (mcrypt.blocksize)
            {
                cnt = ((cnt - 1) / mcrypt.blocksize + 1) * mcrypt.blocksize; // pad to block size
                mdecrypt_generic(mcrypt.td, buff, cnt);
                mcrypt_enc_set_state(mcrypt.td, mcrypt.enc_state, mcrypt.enc_state_size);
            }
            write(kcps->dev_fd, (void *)buff, cnt);
        }
        isleep(1);
    }
}

void update_loop(struct kcpsess_st *kcps)
{
    while (1)
    {
        if (kcps->kcp) {
            pthread_mutex_lock(&ikcp_mutex);
            ikcp_update(kcps->kcp, iclock());
            pthread_mutex_unlock(&ikcp_mutex);
        }
        isleep(1);
    }

}
