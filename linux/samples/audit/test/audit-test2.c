#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libaudit.h>
#include <getopt.h>
#include "regexplib.h"
#include "sysname.h"
#include <pthread.h>

pthread_mutex_t	mx;
pthread_t	th;

static int	iter = 20;
static int	verbose = 0;
static char	buf[MAX_AUDIT_MESSAGE_LENGTH];
static char	path[1024];

static void*
foo(void *f)
{
    int i;
    printf("Thread is running\n");
    pthread_mutex_lock(&mx);
    printf("Thread Locked\n");
    for (i = 0; i < 10; i++) {
	printf("hello\n");
    }
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
    //rc = audit_rule_syscallbyname_data(rule, "all");
    rc = audit_rule_syscallbyname_data(rule, "openat");
    if (rc != 0) {
	fprintf(stderr, "audit_rule_syscallbyname_data() fails: %d\n", rc);
	exit(-1);
    }
    rc = audit_rule_syscallbyname_data(rule, "open");
    if (rc != 0) {
	fprintf(stderr, "audit_rule_syscallbyname_data() fails: %d\n", rc);
	exit(-1);
    }
    rc = audit_rule_syscallbyname_data(rule, "write");
    if (rc != 0) {
	fprintf(stderr, "audit_rule_syscallbyname_data() fails: %d\n", rc);
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
#ifdef NONBLOCKING
    FD_ZERO(&mask);
    FD_SET(fd, &mask);
#endif

    pthread_mutex_unlock(&mx);
    //clock();
    for (i = 0; i < iter; i++) {
	audit_get_reply(fd, &reply, GET_REPLY_BLOCKING, 0);
	printf("reply.type=0x%x\n", reply.type);
    }
    //clock();

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
    return 0;
}
