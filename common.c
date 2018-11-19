#include "common.h"

//static std::map<std::string, std::shared_ptr<spdlog::logger>> logmap;
pthread_mutex_t ikcp_mutex = PTHREAD_MUTEX_INITIALIZER;

// std::shared_ptr<spdlog::logger> logger(char const *name)
// {
//     if (logmap.find(name) == logmap.end())
//     {
//         logmap[name] = spdlog::stdout_color_mt(name);
//         spdlog::set_pattern("[%Y-%m-%d %H:%M:%S %z] [thread %t] [%n] %v");
//         spdlog::set_level(spdlog::level::off);
//     }
//     return logmap[name];
// };

void logging(char const *msg, ...)
{
    //printf(msg, ...);
}

struct LOGGER_ST *logger(char const *name)
{
    LOGGER.info = &logging;
    LOGGER.error = &logging;
    return &LOGGER;
};

int init_tap(void)
{
    int dev;
    char tun_device[] = "/dev/net/tun";
    char dev_name[] = "tap%d";
    int tuntap_flag = IFF_TAP;
    struct ifreq ifr;
    if ((dev = open(tun_device, O_RDWR)) < 0)
    {
        logger("init_tap")->info("open({}) failed: {}", tun_device, strerror(errno));
        exit(2);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tuntap_flag | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    if (ioctl(dev, TUNSETIFF, (void *)&ifr) < 0)
    {
        logger("init_tap")->info("ioctl(TUNSETIFF) failed");
        exit(3);
    }
    logger("init_tap")->info("init tap dev success. fd: {}", dev);
    return dev;
};

ikcpcb *init_kcp(struct kcpsess_st *ps, int mode)
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
    return kcp_;
}

void init_mcrypt(struct mcrypt_st *mcrypt)
{
    char key[] = KEY;
    mcrypt->td = mcrypt_module_open(algo, NULL, mode, NULL);
    if (mcrypt->td == MCRYPT_FAILED)
    {
        logger("init_mcrypt")->info("mcrypt_module_open failed algo={} mode={} keysize={}", algo, mode, sizeof(key));
        exit(3);
    }
    mcrypt->blocksize = mcrypt_enc_get_block_size(mcrypt->td);
    mcrypt_generic_init(mcrypt->td, key, sizeof(key), NULL);
    mcrypt->enc_state_size = sizeof mcrypt->enc_state;
    mcrypt_enc_get_state(mcrypt->td, mcrypt->enc_state, &mcrypt->enc_state_size);
};

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
    logger("udp_output")->info("udp_output {}", len);
    struct kcpsess_st *ps = (struct kcpsess_st *)user;
    int cnt = sendto(ps->sock_fd, buf, len, 0, ps->dst, sizeof(*ps->dst));
    if (cnt < 0)
    {
        logger("udp_output")->error("udp send failed");
    }
    return 0;
};

void *udp2kcp(void *data)
{
    char buff[RCV_BUFF_LEN];
    struct kcpsess_st *kcps = (struct kcpsess_st *)data;
    while (1)
    {
        int cnt = recvfrom(kcps->sock_fd, &buff, RCV_BUFF_LEN, 0, kcps->dst, &(kcps->dst_len));
        if (cnt < 0)
        {
            continue;
        }
        logger("udp2kcp")->info("recvfrom udp packet: {}", cnt);
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
        logger("dev2kcp")->info("read data from tap: {}", cnt);
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
            pthread_mutex_lock(&ikcp_mutex);
            int cnt = ikcp_recv(kcps->kcp, buff, RCV_BUFF_LEN);
            pthread_mutex_unlock(&ikcp_mutex);
            if (cnt < 0)
            {
                x++;
                if (x > 2000)
                {
                    logger("kcp2dev")->info("recv no data for 2s.");
                    x = 0;
                }
                break;
            }
            x = 0;
            logger("kcp2dev")->info("recv data from kcp: {}", cnt);
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
    if (kcps->kcp)
    {
        while (1)
        {
            pthread_mutex_lock(&ikcp_mutex);
            ikcp_update(kcps->kcp, iclock());
            pthread_mutex_unlock(&ikcp_mutex);
            isleep(1);
        }
    }
}
