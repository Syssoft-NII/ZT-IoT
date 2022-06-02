/*
 *	-dFM
 *		d: debug,
 *		F: logs written to a file, M: logs via MQTT
 *	server=<url>,logfile=<url>
 *		server=<url>
 *			ex., server=mqtt://ubuntu:1883
 *			(server=mqtts://ubuntu)
 *		logfile=<path>
 *			ex., logfile=/tmp/LOG_audit
 */
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
#include "autestlib.h"
#include "log-field.h"

#define DEBUG	if (dflag)
#define OUT_NONE	0
#define OUT_FILE	1
#define OUT_MQTT	2

int	verbose;
pthread_mutex_t	mx1, mx2, mx3;


static int	mrkr;
static volatile int	finish;
static int	dflag;
static pid_t	mypid;
static long	count;

static char	combuf[MAX_AUDIT_MESSAGE_LENGTH];
static void
handle_event(auparse_state_t *au,
	     auparse_cb_event_t cb_event_type, void *user_data)
{
    int		nrec, syscall, i;

    if (cb_event_type != AUPARSE_CB_EVENT_READY)
	return;
    nrec = auparse_get_num_records(au);
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
		finish = 1;
	    }
	    printf("syscall = %s (%d)\n", sysname[syscall], syscall); fflush(stdout);
	}
    }
    return;
}

/*
 */
int
main(int argc, char **argv)
{
    ssize_t	len;
    int		i, outdev = OUT_NONE, port = 0;
    char	*logfile = NULL, *url = NULL,
		*protocol = NULL, *host = NULL;
    FILE	*fout = NULL;
    auparse_state_t	*au;
    
    mypid = getpid();
    count = 0;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-') {
	    int	j = 1;
	    while(argv[i][j]) {
		switch (argv[i][j]) {
		case 'd':
		    dflag = 1;
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
	    arg_parse(argv[i], &logfile, &url, &protocol, &host, &port);
	}
    }
    printf("*** logfile = %s, url = %s, protocol = %s, host = %s, port = %d\n",
	   logfile, url, protocol, host, port); fflush(stdout);
    switch (outdev) {
    case OUT_FILE:
	fout = fopen(logfile, "w");
	if (fout == NULL) {
	    fprintf(stderr, "Cannot open file %s\n", logfile);
	} else {
	    stdout = fout; stderr = fout;
	}
	break;
    default:
	fprintf(stderr, "Going to standard output file\n");
	break;
    }
    mrkr = search_syscall(MEASURE_FINISH_SYSNAME);
    if (mrkr < 0) {
	printf("The %s system call is not avalabe on your system.\n",
	       MEASURE_FINISH_SYSNAME);
	exit(-1);
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
    printf("<%d> Now listing.....\n", mypid); fflush(stdout);
    while((len = read(0, combuf, MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
	// printf("*** len = %ld\n", len); fflush(stdout);
	auparse_feed(au, combuf, len);
	++count;
	if (finish) break;
    }
    printf("EXITING\n"); fflush(stdout);
    if (outdev == OUT_FILE && fout != NULL) {
	fclose(fout);
    }
    return 0;
}
