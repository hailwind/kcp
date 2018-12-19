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
#include <pthread.h>
#include <lz4.h>

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include "map.h"
#include "ikcp.h"

#define SERVER_IP "192.168.10.11"
#define SERVER_PORT 8888

#define ENABLED_LOG {"notice", "warning", "handle", "init_tap", "init_mcrypt", "read_fifo"}

//#define DEFAULT_ALLOWED_CONV "28445"

//IKCP PARAMETERS DEFINE
//int nodelay, int interval, int resend, int nc
#define M0_MODE 0, 1, 20, 0
#define M1_MODE 0, 2, 50, 0
#define M2_MODE 0, 2, 20, 0
#define M3_MODE 0, 2, 10, 0
#define M4_MODE 0, 2, 5, 0
#define M5_MODE 0, 2, 50, 1
#define M6_MODE 0, 2, 20, 1
#define M7_MODE 0, 2, 10, 1
#define M8_MODE 0, 2, 5, 1

#define SND_WINDOW 4096
#define RSV_WINDOW 4096
#define RX_MINRTO 20

#define MTU 1400

#define RCV_BUFF_LEN 16384

#define KEY "0123456789012345678901234567890"

#define __NR_gettid 186

struct mcrypt_st
{
    MCRYPT td;
    int blocksize;
    char enc_state[1024];;
    int enc_state_size;
};

struct kcpsess_st
{
    uint32_t conv;
	uint32_t sess_id;
    int dev_fd;
	int sock_fd;
	ikcpcb *kcp;
	char key[33];
    struct sockaddr_in dst;
	socklen_t dst_len;
	uint64_t last_alive_time;
	pthread_t kcp2devt;
	pthread_t dev2kcpt;
	int dead;
	pthread_mutex_t ikcp_mutex;
};

typedef struct kcpsess_st * kcpsess_pt;

struct connection_map_st
{
	int fifo_fd;
	root_t conv_session_map;    //k: conv, v: kcpsess_st
};

struct server_listen_st
{
	int sock_fd;
	struct connection_map_st *conn_map;
};

void logging(char const *name, char const *message, ...);

void init_logging();

void create_pid(char *role, int conv);

void set_debug();

void set_server();

void set_mode(int arq_mode);

void set_lz4();

void set_nocrypt();

void set_mcrypt_algo(char *arg);

void set_mcrypt_mode(char *arg);

int udp_output(const char *buf, int len, ikcpcb *kcp, void *user);

int init_tap(uint32_t conv);

void init_kcp(struct kcpsess_st *ps);

void * udp2kcp_server(void *data);

void * udp2kcp_client(void *data);

void * dev2kcp(void *data);

void * kcp2dev(void *data);

void * kcpupdate_server(void *data);

void kcpupdate_client(struct kcpsess_st *kcps);

/* get system time */
static inline void itimeofday(long *sec, long *usec)
{
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
}

static int64_t timstamp()
{    
	struct timeval tv;    
	gettimeofday(&tv,NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;    
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