#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <mcrypt.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

#include <map>
#include <list>
#include <vector>

#include "ikcp.h"

#define SERVER_IP "192.168.10.11"
#define SERVER_PORT 8888

//IKCP PARAMETERS DEFINE

#define DEFAULT_MODE 0, 10, 0, 0
#define NORMAL_MODE 0, 10, 0, 1
#define FAST_MODE 1, 10, 2, 1

#define SND_WINDOW 8192
#define RSV_WINDOW 8192
#define STREAM_MODE 1
#define RX_MINRTO 10

#define MTU 1450

#define SND_BUFF_LEN 1518
#define RCV_BUFF_LEN 16384

struct mcrypt_st
{
    MCRYPT td;
    int blocksize;
    char *enc_state;
    int enc_state_size;
};

struct kcpsess_st
{
	ikcpcb *kcp;
    int dev_fd;
	int sock_fd;
    int conv;
	char sndbuff[SND_BUFF_LEN];
	char rcvbuff[RCV_BUFF_LEN];
    struct sockaddr *dst;
	socklen_t dst_len;

	// struct sockaddr *src;
	// socklen_t src_len;
};

std::shared_ptr<spdlog::logger> logger(char const *name = "logger");

void init_mcrypt(struct mcrypt_st *mcrypt);

int init_tap(void);

ikcpcb * init_kcp(kcpsess_st *ks, int mode);

void udp2kcp(void *data);

void dev2kcp(void *data);

void kcp2dev(void *data);

void update_loop(kcpsess_st *kcps);

/* get system time */
static inline void itimeofday(long *sec, long *usec)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
}

/* get clock in millisecond 64 */
static inline IINT64 iclock64(void)
{
	long s, u;
	IINT64 value;
	itimeofday(&s, &u);
	value = ((IINT64)s) * 1000 + (u / 1000);
	return value;
}

/* get clock in millisecond 32 */
static inline IUINT32 iclock()
{
	return (IUINT32)(iclock64() & 0xfffffffful);
}

/* sleep in millisecond */
static inline void isleep(unsigned long millisecond)
{
	struct timespec ts;
	ts.tv_sec = (time_t)(millisecond / 1000);
	ts.tv_nsec = (long)((millisecond % 1000) * 1000000);
	/*nanosleep(&ts, NULL);*/
	usleep((millisecond << 10) - (millisecond << 4) - (millisecond << 3));
}