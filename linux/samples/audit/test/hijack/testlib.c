/*
 */
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define __USE_GNU
#include <dlfcn.h>

#define PTR_DECL(name, ret, args)	\
    ret (*__real_ ## name) args = NULL;
    
#define HIJACK(func)				\
    {							\
	if (__this_init == 0) {				\
	    __hijack_init();				\
	}						\
	if (__real_ ## func == NULL) {			\
	    __real_ ## func = dlsym(RTLD_NEXT, #func);	\
	}						\
	if (__real_ ## func == NULL) {			\
	    fprintf(stderr, "Cannot resolve real system call %s\n", #func); \
	    exit(-1); \
	} \
    }

PTR_DECL(write, ssize_t, (int fd, const void *buf, size_t count));
PTR_DECL(read, ssize_t, (int fd, void *buf, size_t count));
PTR_DECL(close, int, (int fd));
PTR_DECL(accept, int, (int sockfd, struct sockaddr *addr, socklen_t *addrlen));

/* Message types */
#define CMD_CONNECT 0x10U
#define CMD_CONNACK 0x20U
#define CMD_PUBLISH 0x30U
#define CMD_PUBACK 0x40U
#define CMD_PUBREC 0x50U
#define CMD_PUBREL 0x60U
#define CMD_PUBCOMP 0x70U
#define CMD_SUBSCRIBE 0x80U
#define CMD_SUBACK 0x90U
#define CMD_UNSUBSCRIBE 0xA0U
#define CMD_UNSUBACK 0xB0U
#define CMD_PINGREQ 0xC0U
#define CMD_PINGRESP 0xD0U
#define CMD_DISCONNECT 0xE0U
#define CMD_AUTH 0xF0U

const char *
cmd_string(unsigned int cmd)
{
    char	*strcmd;
    switch (cmd) {
    case CMD_CONNECT: strcmd = "CONNECT"; break;
    case CMD_CONNACK: strcmd = "CONNACK"; break;
    case CMD_PUBLISH: strcmd = "PUBLISH"; break;
    case CMD_PUBACK: strcmd = "PUBACK"; break;
    case CMD_PUBREC: strcmd = "PUBREC"; break;
    case CMD_PUBREL: strcmd = "PUBREL"; break;
    case CMD_SUBSCRIBE: strcmd = "SUBSCRIBE"; break;
    case CMD_SUBACK: strcmd = "SUBACK"; break;
    case CMD_UNSUBSCRIBE: strcmd = "UNSUBSCRIBE"; break;
    case CMD_UNSUBACK: strcmd = "UNSUBACK"; break;
    case CMD_PINGREQ: strcmd = "PINGREQ"; break;
    case CMD_PINGRESP: strcmd = "PINGRESP"; break;
    case CMD_DISCONNECT: strcmd = "DISCONNECT"; break;
    case CMD_AUTH: strcmd = "AUTH"; break;
    default: strcmd = "UNKNOWN"; break;
    }
    return strcmd;
}

#define BSIZE	256
struct constate {
    int		live;
    int		rc;
    int		fd;
    int		mqtt_head;
    uint8_t	mqtt_cmd;
    uint8_t	mqtt_plen;
    uint16_t	mqtt_rlen;
    uint16_t	pos;
    uint16_t	len;
    uint8_t	buf[BSIZE];
};

static int	__this_init = 0;
static struct constate *cstate;
#define MAX_CSTATE	128 /* FIX MEE */

static void
__hijack_init()
{
    __this_init = 1;
    cstate = malloc(sizeof(struct constate)*MAX_CSTATE);
    memset(cstate, 0, sizeof(struct constate)*MAX_CSTATE);
}


ssize_t
read(int fd, void *buf, size_t count)
{
    ssize_t	ret, tlen;
    struct constate	*csp;

    //fprintf(stderr, "READ %d 0x%p %ld\n", fd, buf, count);
    HIJACK(read);

    csp = &cstate[fd];
    if (csp->live == 0) { /* Do not need capture */
	ret = __real_read(fd, buf, count);
	return ret;
    }
    if (csp->pos == csp->len) {
	csp->rc = __real_read(fd, csp->buf, BSIZE);
	if (csp->rc < 0) {
	    fprintf(stderr, "READ(%d): ERROR(%d), ", fd, csp->rc);
	    ret = csp->rc;
	    goto err;
	}
	fprintf(stderr, "READ(%d): head(%d) len(%d)\n", fd, csp->mqtt_head, csp->rc);
	csp->len = csp->rc;
	csp->pos = 0;
    }
    tlen = count > csp->len ? csp->len : count;
    bcopy(&csp->buf[csp->pos], buf, tlen);
    if (csp->mqtt_head) {
	if (csp->pos + 1 < csp->len) { /* length field also available */
	    csp->mqtt_cmd = csp->buf[csp->pos];
	    csp->mqtt_plen = csp->buf[csp->pos + 1]; // FIX ME: Variable Length
	    fprintf(stderr, "MQTT_CMD=%s(0x%x) MQTT_LEN(%d)\n",
		    cmd_string(csp->mqtt_cmd&0xf0), csp->mqtt_cmd,
		    csp->mqtt_plen);
	} else {
	    fprintf(stderr, "\tUNEXPECTED !!!! FIX ME\n");
	}
	csp->mqtt_head = 0;
	csp->mqtt_rlen = 0;
    }
    csp->mqtt_rlen += tlen;
    fprintf(stderr, "\tmqtt_rlen(%d) mqqt_plen(%d)\n", csp->mqtt_rlen, csp->mqtt_plen);
    if (csp->mqtt_rlen == csp->mqtt_plen + 2) {
	/* looking for head */
	csp->mqtt_head = 1;
    }
    csp->pos += tlen;
    ret = tlen;
    {
	int i;
	fprintf(stderr, "READ(%d): len=%ld act=%ld, ", fd, count, ret);
	for (i = 0; i < ret; i++) {
	    fprintf(stderr, "0x%x ", ((uint8_t*) buf)[i]);
	}
	fprintf(stderr, "\n");
    }
err:
    return ret;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
    ssize_t	ret;

    HIJACK(write);
    fprintf(stderr, "WRITE(%d): len=%ld\n", fd, count);
    ret = __real_write(fd, buf, count);
    return ret;
}

int
close(int fd)
{
    int ret;

    HIJACK(close);
    if (cstate[fd].live) {
	cstate[fd].live = 0;
	cstate[fd].rc = 0;
	cstate[fd].fd = 0;
	cstate[fd].mqtt_head = 1;
    }
    ret = __real_close(fd);
    fprintf(stderr, "CLOSE(%d)\n", fd);
    return ret;
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int	ret;
    HIJACK(accept);
    ret = __real_accept(sockfd, addr, addrlen);
    fprintf(stderr, "ACCEPT(%d) sockfd=%d addr=%p addrlen=%p\n",
	    ret, sockfd, addr, addrlen);
    if (ret >= 0) {
	cstate[ret].live = 1;
	cstate[ret].rc = 0;
	cstate[ret].fd = ret;
	cstate[ret].pos = 0;
	cstate[ret].len = 0;
	cstate[ret].mqtt_head = 1;
    } else {
	perror("accept:");
    }
    return ret;
}

