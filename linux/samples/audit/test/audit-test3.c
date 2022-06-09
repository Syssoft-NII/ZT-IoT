/*
 *	-dFM
 *		d: debug,
 *		F: logs written to a file, M: logs via MQTT
 *	server=<url>,prefix=<url>
 *		server=<url>
 *			ex., server=mqtt://ubuntu:1883
 *			(server=mqtts://ubuntu)
 *		prefix=<path-prefix>
 *			ex., prefix=/tmp/auplugin
 *
 *	TODO: Checking how many records are required for AUDIT_CONFI_CHANG
 */
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <libaudit.h>
#include <auparse.h>
#include <pthread.h>
#include <fcntl.h>
#include "tsc.h"
#include "autestlib.h"
#include "log-field.h"
#include "regexplib.h"

#define OUT_NONE	0
#define OUT_FILE	1
#define OUT_MQTT	2

static volatile int	finish;
static int	dflag = 0;	/* debug */
static int	vflag = 0;	/* verbose */
static int	hflag = 0;	/* header */
static int	nflag = 0;
static char	*prefix = "/tmp/audit-test3";
int		mycore;

static int	mrkr;
static int	iter = 100;
static int	cpu = -1;
static int	syscl;
static uint64_t	aud_st = 0;
static uint64_t	aud_et = 0;
static FILE	*fout = NULL;
static FILE	*fdat = NULL;
static char	fbuf[PATH_MAX];

/*
 */
int
main(int argc, char **argv)
{
    int		i, opt, npkt, cnt;
    int		fd;

    while ((opt = getopt(argc, argv, "hi:vnse:f:dc:")) != -1) {
	switch (opt) {
	case 'c':
	    cpu = atoi(optarg);
	    break;
	case 'd':
	    dflag = 1;
	    break;
	case 'e':
	    syscl = atoi(optarg);
	    if (syscl >= SYS_MAX) {
		fprintf(stderr, "-e option must be smaller than %d\n", SYS_MAX);
		exit(-1);
	    }
	    break;
	case 'i':
	    iter = atoi(optarg);
	    break;
	case 'v':
	    vflag = 1;
	    break;
	case 'n':
	    nflag = 1;
	    break;
	case 'h':
	    hflag = 1;
	    break;
	case 's':
	    i = search_syscall(optarg);
	    if (i < -1) {
		fprintf(stderr, "%s system call is not supported\n", optarg);
		exit(-1);
	    }
	    break;
	case 'f':
	    prefix = strdup(optarg);
	    break;
	}
    }
    if (dflag) {
	fout = fdat = stdout;
    } else {
	/* out_open: if not opened, exits inside out_open() */
	fout = out_open(fbuf, prefix, iter, 0, "info", "txt", fbuf);
	stdout = fout;
	fdat = out_open(fbuf, prefix, iter, 0, "tim", "csv", NULL);
    }
    {	/* nflag == 0: audit function is enabled
	 * core == -1: core is not changed */
	int	*fp = (nflag == 0 ? &fd : NULL);
	int	core = (cpu == -1 ? cpu : (cpu + 1));
	mrkr = clone_init(iter, syscl, vflag, core, fp, 1);
	if (mrkr < 0) {
	    exit(-1);
	}
	stderr = fout;
    }
    regex_init(MAX_AUDIT_MESSAGE_LENGTH);
    npkt = 0; cnt = 0;
    if (nflag) {
	/* starting the appl() function */
	pthread_mutex_unlock(&mx1);
	/* waiting for finishing application */
	pthread_mutex_lock(&mx2);
	goto skip;
    }
    /*
     * starting the appl() function
     */
    pthread_mutex_unlock(&mx1);
    aud_st = tick_time();
    while (1) {
	long	rslt1, rslt2;
	struct audit_reply reply;
	
	audit_get_reply(fd, &reply, GET_REPLY_BLOCKING, 0);
	npkt++;
	if (reply.type == AUDIT_SYSCALL) {
	    reply.message[reply.len] = 0;
	    msg_pid(reply.message, &rslt1);
	    msg_syscall(reply.message, &rslt2);
	    VERBOSE {
		printf("[%d]\tpid(%ld) SYSCALL=%ld = %s\n", cnt, rslt1, rslt2, sysname[rslt2]);
	    }
	    cnt++;
	    if (rslt2 == mrkr) {
		break;
	    }
	} else {
	    VERBOSE {
		printf("reply.type=0x%x\n", reply.type);
	    }
	}
	VERBOSE {
	    fflush(stdout);
	}
    }
    aud_et = tick_time();
    /* waiting for finishing application */
    pthread_mutex_lock(&mx2);
    /*
     * finalizing
     */
skip:
    pthread_mutex_unlock(&mx3);
    VERBOSE {
	printf("%s: going to exiting\n", __func__); fflush(stdout);
    }
    measure_show(syscl, iter, npkt, aud_st, aud_et, hflag, vflag, !nflag);
    measure_dout(fdat, syscl, iter);
    /**/
    VERBOSE {
	printf("%s: EXITING\n", __func__); fflush(stdout);
    }
    {
	time_t	tt;
	time(&tt);
	printf("Measured date: %s\n", ctime(&tt));
    }
    if (fout) fclose(fout);
    if (fdat) fclose(fdat);
    return 0;
}
