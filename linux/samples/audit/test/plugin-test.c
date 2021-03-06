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

#define DEBUG	if (dflag)
#define OUT_NONE	0
#define OUT_FILE	1
#define OUT_MQTT	2

static volatile int	finish;
static int	cflag = 0;	/* application clone */
static int	dflag = 0;	/* debug */
static int	eflag = 0;	/* forcing exit at handle_event level */
static int	vflag = 0;	/* verbose */
static int	hflag = 0;	/* header */
static int	rflag = 0;	/* raw data */
static pid_t	mypid;
int		mycore;
static char	combuf[MAX_AUDIT_MESSAGE_LENGTH];

static int	mrkr;
static int	iter = 100;
static int	cpu = -1;
static int	syscl;
static int	npkt;
static uint64_t	aud_st, aud_et;
static int	outdev = OUT_NONE;
static FILE	*fout = NULL;
static FILE	*fdat = NULL;

static int	stop = 0, sighup = 0;

static void
term_handler(int sig)
{
    stop = 1;
}

static void
hup_handler(int sig)
{
    printf("SIGHUP received\n"); fflush(stdout);
    sighup = 1;
}

#include "config.h"
#include "expression.h"
#include "internal.h"
#include "auparse.h"
static void
info_auparse(auparse_state_t *au)
{
    int	i;
    au_lol *lol = au->au_lo;
    
    for (i = 0; i <= lol->maxi; i++) {
	au_lolnode *cur = &(lol->array[i]);
	printf("cur(%d, %p)->status(%d) type(%d:0x%x)\n",
	       i, cur, cur->status, cur->l->cur->type, cur->l->cur->type);
    }
    fflush(stdout);
}


static void
finalization()
{
    /**/
    VERBOSE {
	printf("%s: going to exiting\n", __func__); fflush(stdout);
    }
    if (mrkr > 0) {
	/* waiting for finishing application */
	pthread_mutex_lock(&mx2);
	measure_show(syscl, iter, npkt, aud_st, aud_et, hflag, vflag, 1);
	if (fdat) {
	    measure_dout(fdat, syscl, iter);
	    fclose(fdat);
	}
	pthread_mutex_unlock(&mx3);
    }
    VERBOSE {
	printf("%s: EXITING\n", __func__); fflush(stdout);
    }
    {
	time_t	tt;
	time(&tt);
	printf("Measured date: %s\n", ctime(&tt));
    }
    if (outdev == OUT_FILE && fout != NULL) {
	fclose(fout);
    }
    fclose(stdin);
}

static void
handle_event(auparse_state_t *au,
	     auparse_cb_event_t cb_event_type, void *user_data)
{
    int		nrec, syscall, i;

    if (cb_event_type != AUPARSE_CB_EVENT_READY)
	return;
    nrec = auparse_get_num_records(au);
    //printf("%s: nrec=%d\n", __func__, nrec);
    for (i = 0; i < nrec; i++) {
	int	type;
	auparse_goto_record_num(au, i);
	type = auparse_get_type(au);
	if (type == AUDIT_SYSCALL) {
	    pid_t	pid;
	    auparse_goto_field_num(au, PARAM_SYSCALL_PID);
	    pid = atoi(auparse_get_field_str(au));
	    if (pid == mypid) {
		break;
	    }
	    auparse_goto_field_num(au, PARAM_SYSCALL_NUM);
	    syscall = atoi(auparse_get_field_str(au));
	    if (syscall == mrkr) {
		finish++;
		if (finish == 1) {
		    /* tick time is now at this time */
		    aud_et = tick_time();
		}
		if (eflag) {
		    finalization();
		    exit(0);
		}
		VERBOSE {
		    printf("%s: FINISHING\n", __func__); fflush(stdout);
		    /* In case of running without eflag,
		     * we will receive the more marker. This is because
		     * the main routine might not terminate until the next
		     * event. (Do we need more events ?) */
		}
	    }
	    VERBOSE {
		printf("syscall = %s (%d)\n", sysname[syscall], syscall); fflush(stdout);
	    }
	} else {
	    VERBOSE {
		printf("type = %d (0x%x)\n", type, type); fflush(stdout);
	    }
	}
    }
    return;
}

/*
 */
int
main(int argc, char **argv)
{
    int		i, port = 0;
    char	*prefix = "plugin-test";
    char	*url = NULL,
		*protocol = NULL, *host = NULL;
    auparse_state_t	*au;

    mypid = getpid();
    npkt = 0;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-') {
	    int	j = 1;
	    while(argv[i][j]) {
		switch (argv[i][j]) {
		case 'c':
		    cflag = 1;
		    break;
		case 'd':
		    dflag = 1;
		    break;
		case 'e':
		    eflag = 1;
		    break;
		case 'h':
		    hflag = 1;
		    break;
		case 'r':
		    rflag = 1;
		    break;
		case 'v':
		    vflag = 1;
		    hflag = 1;
		    break;
		case 'F':
		    outdev = OUT_FILE;
		    break;
		case 'M':
		    outdev = OUT_MQTT;
		    break;
		default:
		    printf("%s: Unknown option: %s\n", argv[0], argv[i]);
		}
		j++;
	    }
	} else {
	    arg_parse(argv[i], &prefix, &url, &protocol, &host, &port,
		      &iter, &cpu, NULL);
	}
    }
    /* core binding */
    mycore = core_bind(cpu);
    {	/* Register sighandlers */
	struct sigaction sa;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
    }
    printf("*** prefix = %s, url = %s, protocol = %s, host = %s, port = %d iter = %d mycore = %d\n",
	   prefix, url, protocol, host, port, iter, mycore);
    fflush(stdout);
    switch (outdev) {
    case OUT_FILE:
    {
	char	fbuf[PATH_MAX];
	fout = out_open(fbuf, prefix, iter, 0, "info", "txt", NULL);
	stdout = fout; stderr = fout;
	if (rflag) {
	    fdat = out_open(fbuf, prefix, iter, 0, "tim", "csv", NULL);
	}
	break;
    }
    default:
	fprintf(stderr, "Going to standard output file\n");
	break;
    }
    /* Initialize the auparse library */
    au = auparse_init(AUSOURCE_FEED, 0);
    if (au == NULL) {
	printf("%s is exiting due to auparse init errors\n", argv[0]);
	return -1;
    }
    auparse_set_eoe_timeout(2);
    auparse_add_callback(au, handle_event, NULL, NULL);
    /**/
    if (cflag) {
	int	fd;
	syscl = 1;
	printf("%s: syscl = %d\n", __func__, syscl); fflush(stdout);
	if (cpu == -1) { /* core is not changed */
	    mrkr = clone_init(iter, syscl, vflag, -1, &fd, 0);
	} else { /* next to the core */
	    mrkr = clone_init(iter, syscl, vflag, mycore + 1, &fd, 0);
	}
	if (mrkr < 0) {
	    goto err;
	}
	printf("<%d> Now Ready for basic measurement.(marker=%d, fd=%d)....\n", mypid, mrkr, fd); fflush(stdout);
	/* starting the appl() function */
	pthread_mutex_unlock(&mx1);
    } else {
	printf("<%d> Now listing.....\n", mypid); fflush(stdout);
    }
    aud_st = tick_time();
    {
	size_t len;
    loop:
	while((len = read(0, combuf, MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
	    //printf("*** len = %ld\n", len); fflush(stdout);
	    //printf("*** msg(%ld) = %s\n", len, combuf); fflush(stdout);
	    npkt++;
	    if (auparse_feed(au, combuf, len) < 0) {
		printf("%s: auparse_feed error\n", __func__); fflush(stdout);
	    }
	    if (auparse_feed_has_data(au)) {
		auparse_feed_age_events(au);
	    }
	    if (finish || sighup) break;
	}
	if (sighup) {
	    info_auparse(au);
	}
	if (finish == 0) {
	    goto loop;
	}
    }
    aud_et = tick_time();
err:
    finalization();
    return 0;
}
