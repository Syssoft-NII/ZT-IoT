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
#include "mqtt_testlib.h"

#define DEBUG	if (dflag)
#define OUT_NONE	0
#define OUT_FILE	1
#define OUT_MQTT	2

static volatile int	finish;
static auparse_state_t	*au;
static void	*mosq;
static void	*mqtt_mx;
static uint64_t	npublished = 0;
static uint64_t	nevent = 0;
static int	mflag = 0;	/* MQTT send */
static int	cflag = 0;	/* application clone */
static int	dflag = 0;	/* debug */
static int	eflag = 0;	/* forcing exit at handle_event level */
static int	vflag = 0;	/* verbose */
static int	hflag = 0;	/* header */
static int	rflag = 0;	/* raw data */
static pid_t	mypid;
int		mycore;
static char	combuf[MAX_AUDIT_MESSAGE_LENGTH];
//static char	dbgbuf[MAX_AUDIT_MESSAGE_LENGTH+1];

static int	mrkr;
static int	iter = 100;
static int	cpu = -1;
static int	sysnum;
static int	syscl = 1; /* default is getuid */
static int	npkt;
static uint64_t	aud_st, aud_et;
static int	outdev = OUT_NONE;
static FILE	*fout = NULL;
static FILE	*fdat = NULL;

static int	stop = 0, sighup = 0;
#define MQTT_TOPIC	"/audit/12345";
#define MQTT_MSG_SZ	512
#define MAX_INFLIGHT	10000
static char	mybuffer[MAX_INFLIGHT][MQTT_MSG_SZ];
static int	my_prod, my_cons;
static uint64_t	my_nsend, my_nack;
#define MYBUFCNT_UPDATE(val) (val = (val + 1)%MAX_INFLIGHT)

static void
buffer_init()
{
    memset(mybuffer, 0, sizeof(mybuffer));
    my_prod = my_cons = 0;
    my_nsend = my_nack= 0;
}

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
    if (mflag) {
	mqtt_mxsignal(mqtt_mx);
    }
}

static void mypublish();

static void
handle_event(auparse_state_t *au,
	     auparse_cb_event_t cb_event_type, void *user_data)
{
    int		nrec, syscall, i;

    if (cb_event_type != AUPARSE_CB_EVENT_READY)
	return;
    nevent++;
    nrec = auparse_get_num_records(au);
    //printf("%s: nrec=%d\n", __func__, nrec); fflush(stdout);
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
		//printf("%s: !!!! Receiving MARKER finish(%d), eflag(%d)\n", __func__, finish, eflag);
		if (finish == 1) {
		    if (my_nsend != my_nack) {
			//printf("%s: Waiting for publish ACK\n", __func__);
			mqtt_mxwait(mqtt_mx);
			//printf("%s: RESUME\n", __func__);
		    }
		    /* tick time is now at this time */
		    aud_et = tick_time();
		    printf("%s: npublished = %ld nevent = %ld\n", __func__, npublished, nevent); fflush(stdout);
		    mqtt_fin(mosq);
		    measure_show(syscl, iter, npkt, aud_st, aud_et, hflag, vflag, 1);
		    if (fdat) {
			measure_dout(fdat, syscl, iter);
			fclose(fdat);
		    }
		    exit(0);
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
	    } else {
		if (mflag) { /* here we are going to publish */
//		    char	*topic = MQTT_TOPIC;
//		    int		len = MQTT_MSG_SZ;
//		    int		rc;
#if 0
		    printf("%s: syscall %s (%d) my_prod(%d) my_cons(%d) my_nsend(%ld) my_ack(%ld)\n",
			   __func__, sysname[syscall], syscall,
			   my_prod, my_cons, my_nsend, my_nack);
#endif
		    if (syscall != sysnum) {
			printf("%s: syscall %s (%d) my_prod(%d) my_cons(%d) my_nsend(%ld) my_ack(%ld)\n",
			       __func__, sysname[syscall], syscall,
			       my_prod, my_cons, my_nsend, my_nack);
			/* exit loop */
			break;
		    }
		    if (my_nsend == my_nack) {
			/* No inflight message */
			//printf("\t CALLING mypublish!!!\n");
			memcpy(mybuffer[my_prod], combuf, MQTT_MSG_SZ);
			MYBUFCNT_UPDATE(my_prod);
			mypublish();
			/* reset my_nsend and my_nack */
			my_nsend = 1; my_nack = 0;
		    } else {
			/* still not yet done, enqueue */
			//printf("\t ENQUEUE!!!\n");
			memcpy(mybuffer[my_prod], combuf, MQTT_MSG_SZ);
			MYBUFCNT_UPDATE(my_prod);
		    }
		}
	    }
	    VERBOSE {
		printf("syscall = %s (%d)\n", sysname[syscall], syscall); fflush(stdout);
	    }
	    /* exit loop */
	    break;
	} else {
	    VERBOSE {
		printf("type = %d (0x%x)\n", type, type); fflush(stdout);
	    }
	}
    }
    return;
}

static void
mypublish()
{
    char	*topic = MQTT_TOPIC;
    int		len = MQTT_MSG_SZ;
    // int	rc;

    my_nack++;
#if 0
    printf("%s: finish(%d) my_nsend(%ld) my_nack(%ld) "
	   "my_prod(%d) my_cons(%d) npublished(%d) npkt(%d) eflag(%d)\n",
	   __func__, finish, my_nsend, my_nack,
	   my_prod, my_cons, npublished, npkt, eflag); fflush(stdout);
#endif
    if (finish
	&& my_nsend == my_nack
	&& my_prod == my_cons) {
	printf("%s: SIGNAL !!!!\n", __func__); fflush(stdout);
	mqtt_mxsignal(mqtt_mx);
    }
    if (my_prod != my_cons) {
	int	rc;
	//printf("\t !!!! MQTT_PUBLISH: topic= \"%s\", len= %d\n", topic, len); fflush(stdout);
	rc = mqtt_publish(mosq, NULL, topic, len, mybuffer[my_cons], 1, 0);
	if (rc != 0) {
	    printf("%s: mqtt_publish returns error (%d)\n",
		   __func__, rc);
	}
	my_nsend++;
	MYBUFCNT_UPDATE(my_cons);
	npublished++;
    }
}

/*
 */
int
main(int argc, char **argv)
{
    int		i;
    char	*prefix = "plugin-test";
    char	*url = NULL;
    char	*protocol = NULL;
    char	*host = "localhost";
    int		port = 1883;
    int		keepalive = 60;

    mypid = getpid();
    npkt = 0;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-') {
	    int	j = 1;
	    while(argv[i][j]) {
		switch (argv[i][j]) {
		case 'm': /* MQTT */
		    mflag = 1;
		    break;
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
		      &iter, &cpu, &syscl);
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
    if (mflag) {
	buffer_init();
	mosq = mqtt_init(host, port, keepalive, iter, vflag);
	printf("%s: MQTT Paratial Initialized(%p)\n", __func__, mosq);
	if (mosq == NULL) {
	    printf("%s: ERRO EXITING (%p)\n", __func__, mosq);
	    return -1;
	}
	mqtt_publish_callback_set(mosq, mypublish);
	mqtt_mx = mqtt_mxalloc();
	printf("%s: MQTT LOOP START(%p)\n", __func__, mosq); fflush(stdout);
	mqtt_loop_start(mosq);
	printf("%s: Waiting for MQTT connection complete(%p)\n", __func__, mosq);
	while (mqtt_connected == 0) {
	}
	printf("%s: Connected(%p)\n", __func__, mosq);
    }
    /* adhoc hakking now */
    switch (syscl) {
    case SYS_GETID: sysnum = 172; break;
    case SYS_GETUID: sysnum = 174; break;
    default:
	printf("Unknown sysnumber: syscl = %d\n", syscl);
	sysnum = 0;
    }
    if (cflag) {
	int	fd;
	printf("%s: syscl = %d sysnum = %d\n", __func__, syscl, sysnum); fflush(stdout);
	if (cpu == -1) { /* core is not changed */
	    mrkr = clone_init(iter, syscl, vflag, -1, &fd, 0);
	} else { /* next to the core */
	    mrkr = clone_init(iter, syscl, vflag, mycore + 1, &fd, 0);
	}
	if (mrkr < 0) {
	    goto err;
	}
	printf("<%d> Now Ready for basic measurement.(marker=%d, fd=%d, mflag=%d)....\n", mypid, mrkr, fd, mflag); fflush(stdout);
	/* starting the appl() function */
	pthread_mutex_unlock(&mx1);
    } else {
	printf("<%d> Now listing.....\n", mypid); fflush(stdout);
    }
    if (mflag) {
	size_t len;
	aud_st = tick_time();
	/* The same logic of just receiving here,
	 * but the handle_event logic is different */
	while((len = read(0, combuf, MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
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
	return 0;
    } else {
	size_t len;
	aud_st = tick_time();
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
