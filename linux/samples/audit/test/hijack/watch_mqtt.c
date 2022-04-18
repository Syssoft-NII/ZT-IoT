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
#include "watch_mqtt.h"

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

static int	__this_init = 0;
static struct constate *cstate;
#define MAX_CSTATE	128 /* FIX MEE */

static void
__hijack_init()
{
    __this_init = 1;
    cstate = malloc(sizeof(struct constate)*MAX_CSTATE);
    if (cstate == NULL) {
	fprintf(stderr, "Cannot allocate memory\n");
	exit(-1);
    }
    memset(cstate, 0, sizeof(struct constate)*MAX_CSTATE);
}


ssize_t
read(int fd, void *buf, size_t count)
{
    ssize_t	len;
    struct constate	*csp;

    //fprintf(stderr, "READ %d 0x%p %ld\n", fd, buf, count);
    HIJACK(read);

    csp = &cstate[fd];
    if (csp->live == 0) { /* Do not need capture */
	len = __real_read(fd, buf, count);
	return len;
    }
    fprintf(stderr, "READ(%d): count(%ld) csp->pos(%d) csp->len(%d)\n", fd, count, csp->pos, csp->len);
    if (csp->pos == csp->len) {
	__mqtt_protocol(fd, csp, __real_read);
	if (csp->rc < 0) {
	    len = csp->rc;
	    goto err;
	}
    }
    /* copy data to the user buffer */
    len = count > csp->len ? csp->len : count;
    bcopy(&csp->buf[csp->pos], buf, len);
    /* update position */
    csp->pos += len;
    {
	int i;
	fprintf(stderr, "\t: len=%ld act=%d, ", count, csp->len);
	for (i = 0; i < len; i++) {
	    fprintf(stderr, "0x%x ", ((uint8_t*) buf)[i]);
	}
	fprintf(stderr, "\n");
    }
err:
    return len;
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
	cstate[fd].mqtt_state = 0;
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
	cstate[ret].mqtt_state = 0;
    } else {
	perror("accept:");
    }
    return ret;
}

