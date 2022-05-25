#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libaudit.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>
#include "regexplib.h"
#include "sysname.h"
#include "tsc.h"

#define TIME_APP	0
#define TIME_AUDIT	1
#define TIME_MAX	2

static uint64_t	tm_st[TIME_MAX], tm_et[TIME_MAX], hz;
char	*tm_msg[TIME_MAX] = {
  "Application",
  "Audit",
};
static pthread_mutex_t	mx;
static pthread_t	th;

static int	iter = 20;
static int	verbose = 0;
static char	buf[MAX_AUDIT_MESSAGE_LENGTH];
static char	path[1024];

static void*
foo(void *f)
{
    int i, fd;
    printf("Thread is running. iter = %d\n", iter);
    pthread_mutex_lock(&mx);
    tm_st[TIME_APP] = tick_time();
    for (i = 0; i < iter; i++) {
	getpid();
    }
    tm_et[TIME_APP] = tick_time();
    fd = open("/tmp/123", O_RDWR);
    if (fd > 0) {
	close(fd);
    }
    printf("Exiting\n");
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
    int	i, opt, rc, fd, pid;
    long	rslt, rslt2, rslt3;
    struct audit_rule_data *rule;
    struct audit_reply reply;
#ifdef NONBLOCKING
    fd_set	mask;
#endif

    hz = tick_helz( 0 );
    printf("hz(%ld)\n", hz);
    if (hz == 0) {
	printf("Cannot obtain CPU frequency\n");
	exit(-1);
    }

    while ((opt = getopt(argc, argv, "i:v")) != -1) {
	switch (opt) {
	case 'i':
	    iter = atoi(optarg);
	    break;
	case 'v':
	    verbose = 1;
	    break;
	}
    }

    pthread_mutex_init(&mx, 0);
    pthread_mutex_lock(&mx);
    pthread_create(&th, NULL, foo, 0);

    /* A process may access the audit kernel facility via netlink */
    fd = audit_open();
    if (fd < 0) {
	perror("audit_open: ");
	exit(-1);
    }
    pid = getpid();
    /* This process becomes audit daemon process */
    rc = audit_set_pid(fd, pid, WAIT_YES);
    if (rc <= 0) {
	fprintf(stderr, "The process %d cannot become an audit daemon\n", pid);
	exit(-1);
    }
    /* The man page of audit_rule_create_data() is not written.
     * It allocates a memory area using malloc(), and thus, it should be
     * deallocated by free() */
    rule = audit_rule_create_data();
    if (rule == NULL) {
	fprintf(stderr, "Cannot allocate an audit rule structure\n");
	exit(-1);
    }
    rc = audit_rule_syscallbyname_data(rule, "getpid");
    if (rc != 0) {
	fprintf(stderr, "audit_rule_syscallbyname_data(\"getpid\") fails: %d\n", rc);
	exit(-1);
    }
    /* 
     * Adding a new audit rule.
     *   The return value of audit_dd_rule_data function is seq #, > 0 
     *   See __audit_send() function in audit-userspace/lib/netlink.c
     */
    rc = audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    if (rc <= 0) {
	fprintf(stderr, "audit_add_rule_data() fails: %d\n", rc);
	exit(-1);
    }

    /* Enabling the audit system to capture system calls */
    rc = audit_set_enabled(fd, 1);
    if (rc <= 0) {
	fprintf(stderr, "audit_set_enabled() fails: %d\n", rc);
	exit(-1);
    }
    regex_init(MAX_AUDIT_MESSAGE_LENGTH);
    pthread_mutex_unlock(&mx);
    tm_st[TIME_AUDIT] = tick_time();
//    for (i = 0; i < iter * 10; i++) {
    while (1) {
	audit_get_reply(fd, &reply, GET_REPLY_BLOCKING, 0);
	if (reply.type == AUDIT_SYSCALL) {
	    reply.message[reply.len] = 0;
	    rc = msg_syscall(reply.message, &rslt);
	    printf("[%d]\tSYSCALL=%ld = %s\n", i, rslt, sysname[rslt]);
	}
	if (verbose) {
	    printf("reply.type=0x%x\n", reply.type);
	}
    }
    tm_et[TIME_AUDIT] = tick_time();
    /*
     * finalizing
     */
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
    for (i = 0; i < TIME_MAX; i++) {
	printf("%s: %12.9f msec\n",
	       tm_msg[i],
	       (double)(tm_et[i])/(double)(hz/1000) - (double)(tm_st[i])/(double)(hz/1000));
    }
    return 0;
}
