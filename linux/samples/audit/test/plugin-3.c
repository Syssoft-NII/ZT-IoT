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
#include "sysname.h"
#include "log-field.h"
#include "comlib.h"

#define DEBUG	if (dflag)

#define COM_STDOUT	0
#define COM_MQTT	1

#define MAX_ARGS	128
#define MAX_PARAMS	48
const char	*params_syscall[MAX_PARAMS];
const char	*params_mmap[MAX_PARAMS];
const char	*params_paths[16];		/* FIXME */
const char	*params_etc[MAX_PARAMS];
char	proctitle[MAX_AUDIT_MESSAGE_LENGTH];
const char	*cwd;
const char	*saddr;
int	npath;

int	cmethod;
int	dflag, comdflag;
pid_t	mypid;
long	count;
int	msock;

int	execve_argc;
const char	*execve_args[MAX_ARGS];
#define LOG_FILE	"/tmp/LOG_AUDIT"
char	combuf[MAX_AUDIT_MESSAGE_LENGTH];
char	mmsg[MAX_AUDIT_MESSAGE_LENGTH];
char	mheader[MAX_AUDIT_MESSAGE_LENGTH];
int	mlen;
auparse_state_t	*au;
char	*argv[5];

extern int	exec_cmd(char *cmd, char **argv, char *header, char *msg);

void
mqtt_publish()
{
#if 0
    char	*cmd = "/usr/local/bin/mosquitto_pub";
    argv[0] = "mosquitto_pub";
    argv[1] = "-t";
    argv[2] = mheader;
    argv[3] = "-l";
    argv[4] = 0;
    exec_cmd(cmd, argv, mheader, mmsg);
#endif
    if (mlen > 0) {
	switch(cmethod) {
	case COM_STDOUT:
	    printf("%s = %s\n", mheader, mmsg);
	    break;
	case COM_MQTT:
	    mqtt_pub(mheader, mmsg);
	    break;
	}
	mlen = 0;
    }
}

void
mqtt_mkmsg(const char *fmt, ...)
{
    va_list	ap;
    va_start(ap, fmt);
    mlen += vsnprintf(&mmsg[mlen], MAX_AUDIT_MESSAGE_LENGTH, fmt, ap);
    va_end(ap);
    return;
}

void
mqtt_mkheaderstamp(const char *pid, const au_event_t *evnt)
{
    snprintf(mheader, MAX_AUDIT_MESSAGE_LENGTH,
	     "/IOT/XXX/%s/audit", pid);
    mlen = 0;
    mqtt_mkmsg(" %lu.%d:%lu", evnt->sec, evnt->milli, evnt->serial);
    return;
}

static void cleanup_params(const char **area)
{
    int	i;
    for (i = 0; i < MAX_PARAMS; i++) {
	area[i] = NULL;
    }
}

void cleanup()
{
    cwd = 0; saddr = 0; proctitle[0] = 0; npath = 0;
    execve_argc = -1;
    cleanup_params(params_syscall);
    cleanup_params(params_mmap);
    cleanup_params(params_etc);
}


static char
_h2a(const char *p)
{
    int	i, v, val = 0;

    for (i = 0; i < 2; i++) {
	val = val * 16;
	v = *(p + i) - '0';
	if (v >= 0 && v <= 9) {
	    val += v;
	} else {
	    val += (*(p + i) - 'A' + 10);
	}
    }
    return val;
}

/* return value is "int" instead of size_t */
int
hex2ascii(const char *hex, char *asc)
{
    int	idx = 0;
    size_t	sz = 0;
    while (*(hex+idx) != 0) {
	char	ch = _h2a(hex+idx);
	*asc++ = ch;
	if (ch == 0) goto ext;
	idx += 2;
	sz++;
    }
    *asc = 0;
ext:
    return sz;
}

/*
 * SIGTERM handler
 */
static void term_handler(int sig)
{
    printf("SIGTERM is catched\n");
    exit(-1);
}

static int catch_hup;
/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig)
{

    catch_hup = 1;
    printf("SIGHUP is catched. count is now %ld\n", count);
    fflush(stdout);
}

static void
handle_event(auparse_state_t *au,
	     auparse_cb_event_t cb_event_type, void *user_data)
{
    const au_event_t	*evnt;
    int		nrec, tot_args, syscall, i;
    char	*cmd;

    if (cb_event_type != AUPARSE_CB_EVENT_READY)
	return;
    evnt = auparse_get_timestamp(au);
    nrec = auparse_get_num_records(au);
    // printf("EVENT(%ld): nrec(%d)\n", count, nrec);
    tot_args = 0; syscall = -1;
    cleanup();
    for (i = 0; i < nrec; i++) {
	const char	*cp;
	int	j, fnum, type;
	auparse_goto_record_num(au, i);
	type = auparse_get_type(au);
	cp = audit_msg_type_to_name(type);
	fnum = auparse_get_num_fields(au);
	if (fnum > MAX_PARAMS) {
	    printf("# of Fields is larger than expected(%d > %d)\n",
		   fnum, MAX_PARAMS);
	    fnum = MAX_PARAMS;
	}
	//printf("type(%d) fnum(%d)\n", type, fnum); fflush(stdout);
	// printf("t\tRAWTEXT=\"%s\"\n", auparse_get_record_text(au)); fflush(stdout);
	switch (type) {
	case AUDIT_SYSCALL:
	{
	    pid_t	pid;
	    const char	*suc, *ext;
	    
	    for (j = 0; j < fnum; j++) {
		auparse_goto_field_num(au, j);
		params_syscall[j] = auparse_get_field_str(au);
	    }
	    pid = atoi(params_syscall[PARAM_SYSCALL_PID]);
	    if (pid == mypid) {
		// printf("\tMYEVENT pid(%d) mypid(%d)\n", pid, mypid);
		goto ext;
	    }
	    if (syscall != -1) {
		printf("!!!!!!!!!!!! ???? syscall (%d) newone(%d)\n",
		       syscall, atoi(params_syscall[PARAM_SYSCALL_NUM]));
	    }
	    syscall = atoi(params_syscall[PARAM_SYSCALL_NUM]);
	    break;
	}
	case AUDIT_PATH:
	    auparse_goto_field_num(au, 2);
	    params_paths[npath++] =  auparse_get_field_str(au);
	    // printf("\tPATH=%s\n", params_path[PARAM_PATH_PATH]);
	    break;
	case AUDIT_PROCTITLE:
	    auparse_goto_field_num(au, 1);
	    cp = auparse_get_field_str(au);
	    hex2ascii(cp, proctitle);
	    //printf("\tPROCTITLE=%s\n", proctitle);
	    break;
	case AUDIT_SOCKADDR:
	    auparse_goto_field_num(au, 1);
	    saddr = auparse_get_field_str(au);
	    break;
	case AUDIT_CWD:
	    auparse_goto_field_num(au, 1);
	    cwd = auparse_get_field_str(au);
	    //printf("\tCWD=%s\n", cwd);
	    break;
	case AUDIT_EXECVE: /* with clone always ?? */
	{
	    int	k, argc;
	    const char *str_argc;
#if 0
	    {
		int	l, tp;
		const char	*tcp;
		printf("EXECVE: nrec(%d)\n", nrec);
		for (l = 0; l < nrec; l++) {
		    auparse_goto_record_num(au, l);
		    tp = auparse_get_type(au);
		    tcp = audit_msg_type_to_name(tp);
		    printf(" type(%s)", tcp);
		    if (tp == AUDIT_PATH) {
			auparse_goto_field_num(au, 2);
			printf("=\"%s\"", auparse_get_field_str(au));
		    }
		}
		printf("\n");
		/* back to the record */
		auparse_goto_record_num(au, i);
	    }
#endif /* 0 */
	    auparse_goto_field_num(au, 1);
	    str_argc = auparse_get_field_str(au);
	    execve_argc = atoi(str_argc);
	    if (execve_argc > MAX_ARGS) {
		printf("Warning # of argument is too large %d > %d\n", execve_argc, MAX_ARGS);
		execve_argc = MAX_ARGS;
	    }
	    for (k = 0; k < execve_argc; k++) {
		auparse_goto_field_num(au, k + 2);
		execve_args[k] = auparse_get_field_str(au);
	    }
#if 0
	    printf("\tEXECVE=%s, argc = %d(%s), ", cp, execve_argc, str_argc);
	    for (k = 0; k < execve_argc; k++) {
		printf("%s, ", execve_args[k]);
	    }
	    printf("\n");
	    printf("\t\tRAWTEXT=\"%s\"\n", auparse_get_record_text(au));
#endif /* 0 */
	    break;
	}
	case AUDIT_MMAP:
	{
	    const char	*str_fd, *str_flags;
	    for (j = 0; j < fnum; j++) {
		auparse_goto_field_num(au, j);
		params_mmap[j] = auparse_get_field_str(au);
	    }
	    str_fd = params_mmap[PARAM_MMAP_FD];
	    str_flags = params_mmap[PARAM_MMAP_FLAGS];
	    printf("\tMMAP, fd=%s, flags=%s\n", str_fd, str_flags);
	    //printf("t\tRAWTEXT=\"%s\"\n", auparse_get_record_text(au));
	    break;
	}
	case AUDIT_DAEMON_START: /* 1200 */
	    cmd = "DAEMON_START";
	    syscall = -7;
	    goto capture;
	    break;
	case AUDIT_SERVICE_START:
	    cmd = "USER_START";
	    syscall = -6;
	    goto capture;
	case AUDIT_SERVICE_STOP:
	    cmd = "USER_STOP";
	    syscall = -6;
	    goto capture;
	case AUDIT_USER_START: /* same as ACCT */
	    cmd = "USER_START";
	    syscall = -4;
	    goto capture;
	case AUDIT_USER_END: /* same as ACCT */
	    cmd = "USER_END";
	    syscall = -4;
	    goto capture;
	case AUDIT_USER_ACCT:	/* 1101 user system access authorization */
	    cmd = "USER_ACCT";
	    syscall = -4;
	    goto capture;
	case AUDIT_LOGIN:	/* 1006 degfine the login id and info */
	    syscall = -5;
	    goto capture;
	    break;
	case AUDIT_USER_LOGIN:	/* user login, just one record */
	    syscall = -2;
	    goto capture;
	case AUDIT_CRED_DISP: /* same as CRED_ACQ */
	    if (nrec == 1) { /* single record */
		cmd = "CRED_DISP";
		syscall = -3;
	    }
	    goto capture;
	case AUDIT_CRED_ACQ:	/* user credential acquired
				 * with syscall clone record */
	{
	    /* user credential acquired may happen with syscall clone record
	     * or single record */
	    if (nrec == 1) { /* single record */
		cmd = "CRED_ACQ";
		syscall = -3;
	    }
	capture:
	    for (j = 0; j < fnum; j++) {
		auparse_goto_field_num(au, j);
		params_etc[j] = auparse_get_field_str(au);
	    }
	    break;
	}
	case AUDIT_CONFIG_CHANGE: /* 1305 audit system configuration change */
	case AUDIT_USER_AUTH: /* at the login time, by login command */
	    // nrec(1) RAWTEXT="type=USER_AUTH msg=audit(1649727666.885:98021): pid=48131 uid=0 auid=1000 ses=3 subj=unconfined msg='op=PAM:authentication grantors=pam_permit,pam_cap acct="ishikawa" exe="/usr/bin/login" hostname=? addr=? terminal=/dev/pts/7 res=success'"
	default:
	    if (syscall != -1) {
		printf("**UNPROCESSING RAWTEXT=\"%s\"\n", auparse_get_record_text(au));
	    }
	    break;
	}
    }
    DEBUG {
	printf("EVENT(%ld): nrec(%d)\n", count, nrec);
    }
    /*
     * execve system call has the following record
     *	SYSCALL, EXECVE, CWD, PATH, PATH, .. , PROCTITLE
     */
    if (syscall > 0) {
	int	j;
	mqtt_mkheaderstamp(params_syscall[PARAM_SYSCALL_PID], evnt);
	mqtt_mkmsg(" ppid=%s uid=%s gid=%s "
		   "SYSCALL=%s (%d) success(%s) exit(%s) ",
		   params_syscall[PARAM_SYSCALL_PPID],
		   params_syscall[PARAM_SYSCALL_UID],
		   params_syscall[PARAM_SYSCALL_GID],
		   sysname[syscall], syscall,
		   params_syscall[PARAM_SYSCALL_SUCCESS],
		   params_syscall[PARAM_SYSCALL_EXIT]);
	for (j = 0; j < 4; j++) {
	    mqtt_mkmsg(" arg%d(%s)", j, params_syscall[j+PARAM_SYSCALL_A0]);
	}
	mqtt_mkmsg(" npath=%d", npath);
	for (j = 0; j < npath; j++) {
	    mqtt_mkmsg(" PATH=%s", params_paths[j]);
	}
	mqtt_mkmsg(" saddr=%s", (saddr == NULL ? "none" : saddr));
	mqtt_mkmsg(" exec=%s", params_syscall[PARAM_SYSCALL_EXE]);
	//if (proctitle[0] != 0) { printf(" proctitle=%s", proctitle); }
	mqtt_mkmsg(" exec_argc=%d", execve_argc > 0 ? execve_argc : 0);
	//fflush(stdout);
	if (execve_argc > 0) {
	    for (j = 0; j < execve_argc; j++) {
		mqtt_mkmsg(" arg%d=%s", j, execve_args[j]);
	    }
	}
	/* system call# depends on architecture */
	if (strcmp("clone", sysname[syscall]) == 0
	    && params_etc[0] != NULL) {
	    /* CREAD_ACQ event happens also */
	    goto cred_acq;
	}
    } else {
	switch (syscall) {
	case -2:
	/* AUDIT_USER_LOGIN */
	    mqtt_mkheaderstamp(params_etc[PARAMS_USER_LOGIN_PID], evnt);
	    mqtt_mkmsg(" uid=%s auid=%s ses=%s USER_LOGIN subj=%s msg=%s id=%s exe=%s hostname=%s addr=%s terminal=%s res=%s\n",
		       params_etc[PARAMS_USER_LOGIN_UID],
		       params_etc[PARAMS_USER_LOGIN_AUID],
		       params_etc[PARAMS_USER_LOGIN_SES],
		       params_etc[PARAMS_USER_LOGIN_SUBJ],
		       params_etc[PARAMS_USER_LOGIN_MSG],
		       params_etc[PARAMS_USER_LOGIN_ID],
		       params_etc[PARAMS_USER_LOGIN_EXE],
		       params_etc[PARAMS_USER_LOGIN_HOSTNAME],
		       params_etc[PARAMS_USER_LOGIN_ADDR],
		       params_etc[PARAMS_USER_LOGIN_TERMINAL],
		       params_etc[PARAMS_USER_LOGIN_RES]);
	    break;
	case -3: /* Single CRED_ACQ or CRED_DISP event */
	    cred_acq:
	    mqtt_mkheaderstamp(params_etc[PARAMS_CRED_ACQ_PID], evnt);
	    mqtt_mkmsg(" uid=%s auid=%s ses=%s %s subj=%s msg=%s grantors=%s acct=%s exe=%s hostname=%s addr=%s terminal=%s res=%s\n",
		       params_etc[PARAMS_CRED_ACQ_UID],
		       params_etc[PARAMS_CRED_ACQ_AUID],
		       params_etc[PARAMS_CRED_ACQ_SES],
		       cmd,
		       params_etc[PARAMS_CRED_ACQ_SUBJ],
		       params_etc[PARAMS_CRED_ACQ_MSG],
		       params_etc[PARAMS_CRED_ACQ_GRANT],
		       params_etc[PARAMS_CRED_ACQ_ACCT],
		       params_etc[PARAMS_CRED_ACQ_EXE],
		       params_etc[PARAMS_CRED_ACQ_HOSTNAME],
		       params_etc[PARAMS_CRED_ACQ_ADDR],
		       params_etc[PARAMS_CRED_ACQ_TERMINAL],
		       params_etc[PARAMS_CRED_ACQ_RES]);
	    break;
	case -4: /* AUDIT_USER_ACCT */
	    mqtt_mkheaderstamp(params_etc[PARAMS_USER_ACCT_PID], evnt);
	    mqtt_mkmsg(" uid=%s auid=%s ses=%s %s subj=%s msg=%s grantors=%s acct=%s exe=%s hostname=%s addr=%s terminal=%s res=%s\n",
		       params_etc[PARAMS_USER_ACCT_UID],
		       params_etc[PARAMS_USER_ACCT_AUID],
		       params_etc[PARAMS_USER_ACCT_SES],
		       cmd,
		       params_etc[PARAMS_USER_ACCT_SUBJ],
		       params_etc[PARAMS_USER_ACCT_MSG],
		       params_etc[PARAMS_USER_ACCT_GRANT],
		       params_etc[PARAMS_USER_ACCT_ACCT],
		       params_etc[PARAMS_USER_ACCT_EXE],
		       params_etc[PARAMS_USER_ACCT_HOSTNAME],
		       params_etc[PARAMS_USER_ACCT_ADDR],
		       params_etc[PARAMS_USER_ACCT_TERMINAL],
		       params_etc[PARAMS_USER_ACCT_RES]);
	    break;
	case -5: /* AUDIT_LOGIN */
	    mqtt_mkheaderstamp(params_etc[PARAMS_LOGIN_PID], evnt);
	    mqtt_mkmsg(" uid=%s subj=%s old_auid=%s LOGIN auid=%s tty=%s old_ses=%s ses=%s ref=%s\n",
		       params_etc[PARAMS_LOGIN_UID],
		       params_etc[PARAMS_LOGIN_SUBJ],
		       params_etc[PARAMS_LOGIN_OLD_AUID],
		       params_etc[PARAMS_LOGIN_AUID],
		       params_etc[PARAMS_LOGIN_TTY],
		       params_etc[PARAMS_LOGIN_OLD_SES],
		       params_etc[PARAMS_LOGIN_SES],
		       params_etc[PARAMS_LOGIN_RES]);
	    break;
	case -6:
	    mqtt_mkheaderstamp(params_etc[PARAMS_SERVICE_STARTSTOP_PID], evnt);
	    mqtt_mkmsg(" uid=%s auid=%s %s ses=%s subj=%s msg=%s comm=%s exe=%s hostname=%s add=%s terminal=%s res=%s\n",
		       params_etc[PARAMS_SERVICE_STARTSTOP_UID],
		       params_etc[PARAMS_SERVICE_STARTSTOP_AUID],
		       cmd,
		       params_etc[PARAMS_SERVICE_STARTSTOP_SES],
		       params_etc[PARAMS_SERVICE_STARTSTOP_SUBJ],
		       params_etc[PARAMS_SERVICE_STARTSTOP_MSG],
		       params_etc[PARAMS_SERVICE_STARTSTOP_COMM],
		       params_etc[PARAMS_SERVICE_STARTSTOP_EXE],
		       params_etc[PARAMS_SERVICE_STARTSTOP_HOSTNAME],
		       params_etc[PARAMS_SERVICE_STARTSTOP_ADDR],
		       params_etc[PARAMS_SERVICE_STARTSTOP_TERMINAL],
		       params_etc[PARAMS_SERVICE_STARTSTOP_RES]);
	    break;
	case -7:
	    mqtt_mkheaderstamp(params_etc[PARAMS_DAEMON_START_PID], evnt);
	    mqtt_mkmsg(" %s op=%s ver=%s format=%s kernel=%s auid=%s uid=%s ses=%s subj=%s res=%s\n",
		   cmd,
		       params_etc[PARAMS_DAEMON_START_OP],
		       params_etc[PARAMS_DAEMON_START_VER],
		       params_etc[PARAMS_DAEMON_START_FORMAT],
		       params_etc[PARAMS_DAEMON_START_KERNEL],
		       params_etc[PARAMS_DAEMON_START_AUID],
		       params_etc[PARAMS_DAEMON_START_UID],
		       params_etc[PARAMS_DAEMON_START_SES],
		       params_etc[PARAMS_DAEMON_START_SUBJ],
		       params_etc[PARAMS_DAEMON_START_RES]);
	    break;
	default:
	    printf("syscall = %d\n", syscall);
	    printf("\tUNPROCESSING RAWTEXT=\"%s\"\n", auparse_get_record_text(au));
	}
    }
    mqtt_publish();
ext:
    return;
}

void
url_parse(char *cp, char **host, char **proto, int *port)
{
    char	*p, *q;
    /* find ':'  */
    p = index(cp, ':');
    if (p) {
	*p = 0;
	*proto = p;
	p += 1;
    } else {
	*proto = cp;
	/* just protocol */
	return;
    }
    if (!strncmp(p, "//", 2)) {
	p += 2;
	*host = p;
	q = index(p, ':');
	if (q) {
	    *q = 0;
	    q += 1;
	    if (isdigit(*q)) {
		*port = atoi(q);
	    }
	} else { /* just host name */
	    ;
	}
    } else {
	return;
    }
}

/*
 * Though the plugin configuration file specifies more than two arguments,
 * Only two arguments are passed by the audit daemon ;-<
 * Option formats:
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
int
main(int argc, char **argv)
{
    char	*url = NULL;
    char	*protocol = NULL;
    char	*host = "localhost";
    int		port = 1883;
    char	*logfile = LOG_FILE;
    FILE	*fout;
    ssize_t	len;
    struct sigaction sa;
    int	nfds;
    int	i;

    mypid = getpid(); catch_hup = 0;
    count = 0; msock = 0; nfds = 1;
    cmethod = COM_STDOUT; /* default */
    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-') {
	    int	j = 1;
	    while(argv[i][j]) {
		switch (argv[i][j]) {
		case 'd':
		    dflag = 1; comdflag = 1;
		    break;
		case 'F':
		    cmethod = COM_STDOUT;
		    break;
		case 'M':
		    cmethod = COM_MQTT;
		    break;
		default:
		    printf("%s: Unknown option: %s\n", argv[0], argv[i]);
		}
		j++;
	    }
	} else {
#define ARG_SERVER	"server="
#define ARG_LOGFILE	"logfile="
	    char	*nxt;
	    const char	*cp = argv[i];
	    size_t	slen = strlen(ARG_SERVER);
	    size_t	flen = strlen(ARG_LOGFILE);
	    while (*cp) {
		if (!strncmp(ARG_SERVER, cp, slen)) {
		    cp += slen;
		    nxt = index(cp, ',');
		    if (nxt) {
			url = strndup(cp, nxt - cp);
		    } else {
			url = strdup(cp);
		    }
		    url_parse(url, &host, &protocol, &port);
		    if (nxt) {
			cp = nxt + 1;
		    } else {/* no more string */
			break;
		    }
		} else if (!strncmp(ARG_LOGFILE, cp, flen)) {
		    cp += flen;
		    nxt = index(cp, ',');
		    if (nxt) {
			logfile = strndup(cp, nxt - cp);
			cp = nxt + 1;
		    } else {
			logfile = strdup(cp);
			break;
		    }
		} else {
		    break;
		}
	    }
	}
    }
    fout = fopen(logfile, "w");
    if (fout == NULL) {
	fprintf(stderr, "Cannot open file %s\n", logfile);
	return -1;
    }
    stdout = fout; stderr = fout;
    printf("args = ");
    for (i = 0; i < argc; i++) {
	printf("%s ", argv[i]);
    }
    printf("\n");
    switch (cmethod) {
    case COM_MQTT:
	printf("MQTT: server = %s, port = %d, logfile=%s\n", host, port, logfile);
	msock = mqtt_init(host, port, 60);
	nfds++;
	break;
    case COM_STDOUT:
	printf("LOGFILE: file=%s\n", logfile);
	break;
    default:
	printf("Unknown communication method: %d\n", cmethod);
	break;
    }
    fflush(stdout);
    sa.sa_flags = 0; sigemptyset(&sa.sa_mask);
    sa.sa_handler = term_handler;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = hup_handler;
    sigaction(SIGHUP, &sa, NULL);

    /* Initialize the auparse library */
    au = auparse_init(AUSOURCE_FEED, 0);
    if (au == NULL) {
	printf("%s is exiting due to auparse init errors\n", argv[0]);
	return -1;
    }
    auparse_set_eoe_timeout(2);
    auparse_add_callback(au, handle_event, NULL, NULL);
    /**/
    DEBUG {
	switch (cmethod) {
	case COM_STDOUT:
	    printf("Logging to stdout...\n"); break;
	case COM_MQTT:
	    printf("Sending to MQTT broker...\n"); break;
	}
    }
    printf("<%d> Now listing.....\n", mypid); fflush(stdout);
    {
	fd_set read_mask;
	struct timeval tv;
	int	rc;

    loop:
	tv.tv_sec = 0; tv.tv_usec = 100*1000;
	FD_ZERO(&read_mask);
	FD_SET(0, &read_mask); FD_SET(msock, &read_mask);
	rc = select(nfds, &read_mask, NULL, NULL, &tv);
	if (rc == 0) { /* timeout */
	    /* 100 msec polling */
	    if (cmethod == COM_MQTT) {
		mqtt_poll();
	    }
	    goto loop;
	} else if (rc < 0) {
	    printf("select returns %d errno=%d catch_hup=%d\n", rc, errno, catch_hup);
	    perror("\t");
	    goto chk;
	} else {
	    if (FD_ISSET(0, &read_mask)) {
		len = read(0, combuf, MAX_AUDIT_MESSAGE_LENGTH);
		if (len <= 0) goto chk;
		// printf("READ(%ld)==> %s<==READ\n", len, buf); fflush(stdout);
		auparse_feed(au, combuf, len);
		++count;
	    }
	    goto loop;
	}
    chk:
	if (catch_hup) {
	    catch_hup = 0;
	} else {
	    goto ext;
	}
	goto loop;
    }
ext:
    printf("EXITING\n");
    fclose(fout);
    return 0;
}
