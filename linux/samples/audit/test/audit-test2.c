#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libaudit.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <linux/sched.h>
#include "regexplib.h"
#include "sysname.h"
#include "tsc.h"

/* gettid() is the Linux specific system call */
extern int	gettid();

#define VERBOSE	if (verbose)

#define MEASURE_FINISH_SYSNAME	"gettid"
#define MEASURE_FINISH_SYSCALL	{ gettid(); }

#define SYS_GETID	0
#define SYS_GETUID	1
#define SYS_OPEN_CLOSE	2
#define SYS_MAX		3
#define SYS_AUDIT	SYS_MAX
#define TIME_MAX	(SYS_MAX + 1)

struct syscalls {
    int		ncall;
    const char	*sysname[3];
};
struct syscalls systab[SYS_MAX] = {
    { 1, {"getpid", NULL, NULL} },
    { 1, {"getuid", NULL, NULL} },
    { 2, {"openat", "close", NULL} }
};

#define STACK_SIZE	(32*1024)
#define STACK_TOP(addr)	((addr) + STACK_SIZE)

static uint64_t	tm_st[TIME_MAX], tm_et[TIME_MAX], hz;
char	*tm_msg[TIME_MAX] = {
  "getpid",
  "getuid",
  "open&close",
  "Audit",
};
static pthread_mutex_t	mx1, mx2, mx3;

static int	iter = 20;	/* default */
static int	syscl = 0;	/* default */
static int	mrkr;
static struct audit_rule_data *rule;
static int	verbose = 0;
static int	noaudit = 0;
static int	header = 0;

#define MEASURE_SYSCALL(syscl, sysfunc)	{	\
        tm_st[syscl] = tick_time();	\
	for (i = 0; i < iter; i++) {	\
	    sysfunc;	\
	}	\
	tm_et[syscl] = tick_time();	\
	MEASURE_FINISH_SYSCALL;		\
}

static void*
appl(void *f)
{
    int i;

    VERBOSE {
	printf("Cloned-thread is running. stack = %p pid=%d iter = %d\n", &i, getpid(), iter); fflush(stdout);
    }
    /* waiting for unlock by main */
    pthread_mutex_lock(&mx1);
    switch (syscl) {
    case SYS_GETID:
	//MEASURE_SYSCALL(SYS_GETID, gettid());
	MEASURE_SYSCALL(SYS_GETID, getpid());
	break;
    case SYS_GETUID:
	MEASURE_SYSCALL(SYS_GETUID, getuid());
	break;
    case SYS_OPEN_CLOSE:
    {
	char	fname[1024];
	snprintf(fname, 1024, "/tmp/atest-%d", getpid());
	tm_st[syscl] = tick_time();
	for (i = 0; i < iter; i++) {
	    int	fd = open(fname, O_RDWR|O_CREAT, 0666);
	    if (fd < 0) {
		printf("Cannot open file %s\n", fname);
		break;
	    }
	    close(fd);
	}
	tm_et[syscl] = tick_time();
	MEASURE_FINISH_SYSCALL;
	unlink(fname);
	break;
    }
    default:
	fprintf(stderr, "%s: internal error\n", __func__);
	break;
    }
    /* */
    VERBOSE {
	printf("%s: Exiting\n", __func__); fflush(stdout);
    }
    pthread_mutex_unlock(&mx2);
    /* waiting for unlock by main */
    pthread_mutex_lock(&mx3);
    exit(0);
}

static int
search_syscall(char *snam)
{
    int	snum;
    for (snum = 0; snum < SYSCALL_MAX; snum++) {
	if (!strcmp(snam, sysname[snum])) {
	    goto find;
	}
    }
    /* not found */
    snum = -1;
find:
    return snum;
}

static void
init_workarea()
{
    memset(tm_st, 0, sizeof(tm_st));
    memset(tm_st, 0, sizeof(tm_et));
    pthread_mutex_init(&mx1, 0);
    pthread_mutex_init(&mx2, 0);
    pthread_mutex_init(&mx3, 0);
    pthread_mutex_lock(&mx1);
    pthread_mutex_lock(&mx2);
    pthread_mutex_lock(&mx3);
}

static int
init_audit()
{
    int	fd, pid, rc, i;

    pid = getpid();
    fd = audit_open();
    if (fd < 0) {
	perror("audit_open: ");
	exit(-1);
    }
    /* This process becomes audit daemon process */
    rc = audit_set_pid(fd, pid, WAIT_YES);
    if (rc <= 0) {
	fprintf(stderr, "The process %d cannot become an audit daemon\n", pid);
	goto err3;
    }
    /* The man page of audit_rule_create_data() is not written.
     * It allocates a memory area using malloc(), and thus, it should be
     * deallocated by free() */
    rule = audit_rule_create_data();
    if (rule == NULL) {
	fprintf(stderr, "Cannot allocate an audit rule structure\n");
	goto err2;
    }
    /* marker */
    rc = audit_rule_syscallbyname_data(rule, MEASURE_FINISH_SYSNAME);
    /**/
    for (i = 0; i < systab[syscl].ncall; i++) {
	//printf("systab[i]: %s\n",  systab[syscl].sysname[i]);
	rc = audit_rule_syscallbyname_data(rule, systab[syscl].sysname[i]);
	if (rc != 0) {
	    fprintf(stderr, "audit_rule_syscallbyname_data(\"%s\") fails: %d\n", systab[syscl].sysname[i], rc);
	    goto err2;
	}
    }
    /* 
     * Adding a new audit rule.
     *   The return value of audit_dd_rule_data function is seq #, > 0 
     *   See __audit_send() function in audit-userspace/lib/netlink.c
     */
    rc = audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    if (rc <= 0) {
	fprintf(stderr, "audit_add_rule_data() fails: %d\n", rc);
	goto err3;
    }

    /* Enabling the audit system to capture system calls */
    rc = audit_set_enabled(fd, 1);
    if (rc <= 0) {
	fprintf(stderr, "audit_set_enabled() fails: %d\n", rc);
	goto err2;
    }

    regex_init(MAX_AUDIT_MESSAGE_LENGTH);
err1:
    return fd;
err2:
    free(rule);
err3:
    audit_close(fd);
    fd = -1;
    goto err1;
}

static void
finalize_audit(int fd)
{
    int rc;
    /* disable the audit sysytem */
    rc = audit_set_enabled(fd, 0);
    if (rc <= 0) {
	fprintf(stderr, "audit_set_enabled fails: %d\n", rc);
    }
    /* delete the audit rule */
    rc = audit_delete_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    if (rc <= 0) {
	fprintf(stderr, "audit_delete_rule_data fails: %d\n", rc);
    }
    free(rule);
    audit_close(fd);
}

static inline void
verbose_print(struct audit_reply *reply)
{
    if (verbose) {
	printf("event_type=%s len(%d) Message=%.*s\n",
	       audit_msg_type_to_name(reply->type),
	       reply->len, reply->len, reply->message);
    }
}

int
main(int argc, char **argv)
{
    int		i, rc, opt, fd, npkt, cnt;
    int		flags = CLONE_VM
	// CLONE_NEWPID
	// | CLONE_FS | CLONE_IO
	// | CLONE_NEWUTS
		;
    long	rslt1, rslt2;
    void	*stack;
    struct audit_reply reply;

    hz = tick_helz( 0 );
    if (hz == 0) {
	printf("Cannot obtain CPU frequency\n");
	exit(-1);
    }

    while ((opt = getopt(argc, argv, "hi:vnse:")) != -1) {
	switch (opt) {
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
	    verbose = 1;
	    break;
	case 'n':
	    noaudit = 1;
	    break;
	case 'h':
	    header = 1;
	    break;
	case 's':
	    i = search_syscall(optarg);
	    if (i < -1) {
		fprintf(stderr, "%s system call is not supported\n", optarg);
		exit(-1);
	    }
	}
    }

    stack = malloc(STACK_SIZE);
    if (stack == NULL) {
	fprintf(stderr, "Cannot allocate stack memory\n");
	exit(-1);
    }
    memset(stack, 0, STACK_SIZE);
    init_workarea();
    VERBOSE {
	printf("AUDIT PROCESS ID = %d, Stack = %p\n", getpid(),
	       STACK_TOP(stack));
	printf("\thz(%ld)\n", hz);
	printf("\tThe \"%s\" system call (%d) as the marker\n", MEASURE_FINISH_SYSNAME, mrkr);
    }
    clone(appl, STACK_TOP(stack), flags, NULL);

    npkt = 0;
    if (noaudit) {
	/* starting foo function */
	pthread_mutex_unlock(&mx1);
	/* waiting for finishing application */
	pthread_mutex_lock(&mx2);
	goto skip;
    }
    mrkr = search_syscall(MEASURE_FINISH_SYSNAME);
    if (mrkr < 0) {
	printf("The %s system call is not avalabe on your system.\n",
	       MEASURE_FINISH_SYSNAME);
	exit(-1);
    }
    /* 
     * This process may access the audit kernel facility via netlink 
     */
    fd = init_audit();
    /*
     * starting the appl() function
     */
    pthread_mutex_unlock(&mx1);
    cnt = 0;
    tm_st[SYS_AUDIT] = tick_time();
    while (1) {
	audit_get_reply(fd, &reply, GET_REPLY_BLOCKING, 0);
	npkt++;
	if (reply.type == AUDIT_SYSCALL) {
	    reply.message[reply.len] = 0;
	    rc = msg_pid(reply.message, &rslt1);
	    rc = msg_syscall(reply.message, &rslt2);
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
    tm_et[SYS_AUDIT] = tick_time();
    /*
     * finalizing
     */
    finalize_audit(fd);
skip:
#define UNIT	"usec"
#define SCALE	1000000
    if (header) {
	printf("# iteration = %d, syscalls/1iter = %d,  %s/syscall, total: npkt=%d\n", iter, systab[syscl].ncall, UNIT, npkt);
    }
    {
	uint64_t	tclk = tm_et[syscl] - tm_st[syscl];
	double		ttim = (double)tclk/(double)(hz/SCALE);
	/* application */
	printf("%s, %12.9f, %12.9f\n",
	       tm_msg[syscl], (ttim/(double)iter)/systab[syscl].ncall, ttim);
	if (!noaudit) {
	    /* audit */
	    tclk = tm_et[SYS_AUDIT] - tm_st[SYS_AUDIT];
	    ttim = (double)tclk/(double)(hz/SCALE);
	    printf("%s, %12.9f, %12.9f\n",
		   tm_msg[SYS_AUDIT], ttim/(double)iter, ttim);
	}
    }
#if 0
    for (i = 0; i < TIME_MAX; i++) {
	uint64_t	tclk = tm_et[i] - tm_st[i];
	double		ttim = (double)tclk/(double)(hz/SCALE);

	printf("%s, %12.9f, %12.9f\n",
	       tm_msg[i], ttim/(double)iter, ttim);
    }
#endif
    /* signal to foo */
    pthread_mutex_unlock(&mx3);
    return 0;
}
