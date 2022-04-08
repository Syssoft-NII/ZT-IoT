#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libaudit.h>
#include <getopt.h>
#include "regexplib.h"
#include "sysname.h"
#include "monlib.h"

static int	iter = 20;
static int	verbose = 0;
static char	buf[MAX_AUDIT_MESSAGE_LENGTH];
static char	path[1024];

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
    monlst	*mlst;
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

    regex_init(MAX_AUDIT_MESSAGE_LENGTH);
    monlst_init();
    
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
    rc = audit_rule_syscallbyname_data(rule, "all");
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

    for (i = 0; i < iter; i++) {
#ifdef NONBLOCKING
	rc = select(fd + 1, &mask, NULL, NULL, NULL);
    	audit_get_reply(fd, &reply, GET_REPLY_NONBLOCKING, 0);
#else
	audit_get_reply(fd, &reply, GET_REPLY_BLOCKING, 0);
#endif

	reply.message[reply.len] = 0;
	rc = msg_seqnum(reply.message, &rslt, &rslt2, &rslt3);
	mlst = monlst_find(rslt);
	printf("SEQ#%ld (mlst:%p) time=%ld.%ld type(%d)\n", rslt, mlst, rslt2, rslt3, reply.type);
	if (verbose) {
	    printf("\t->%s\n", reply.message);
	}
	switch (reply.type) {
	case AUDIT_SYSCALL:	/* 1300 linux/audit.h */
	    rc = msg_syscall(reply.message, &rslt);
	    printf("\tSYSCALL=%ld = %s\t", rslt, sysname[rslt]);
	    rc = msg_pid(reply.message, &rslt);
	    printf("PID=%ld\n", rslt);
	    break;
	    /* case AUDIT_FS_WATCH: 1301 deprecated */
	case AUDIT_PATH: /* filename path: 1302 */
	    rc = msg_filepath(reply.message, &rslt, path);
	    printf("\t PATH item = %ld path = %s\n", rslt, path);
	    break;
	case AUDIT_CWD: /* current working dir: 1307 */
	    rc = msg_cwd(reply.message, path);
	    printf("\t CWD=%s  MESSAGE=%s\n", path, reply.message);
	    break;
	case AUDIT_IPC: /* IPC record: 1303 */
	case AUDIT_SOCKETCALL: /* sys_socketcall args: 1304 */
	case AUDIT_CONFIG_CHANGE: /* confi change: 1305 */
	case AUDIT_SOCKADDR: /* sockaddr: 1306 */
	case AUDIT_EXECVE: /* execve args: 1309 */
	case AUDIT_IPC_SET_PERM: /* IPC new permissions: 1311 */
	case AUDIT_MQ_OPEN: /* POSIX MQ open record: 1312 */
	case AUDIT_MQ_SENDRECV: /* POSIX MQ send/recv record: 1313 */
	case AUDIT_MQ_NOTIFY: /* POSIX MQ notify record: 1314 */
	case AUDIT_MQ_GETSETATTR: /* POSIX MQ get/set attr. record: 1315 */
	case AUDIT_KERNEL_OTHER: /* for use by 3rd party modules: 1316 */
	case AUDIT_FD_PAIR: /* audit record for pipe/socketpair: 1317 */
	case AUDIT_OBJ_PID: /* ptrace target: 1318 */
	case AUDIT_TTY: /* input on an admin. tty: 1319 */
	    verbose_print(&reply);
	    break;
	case AUDIT_EOE: /* End of multi-record: 1320 */
	    printf("\tEOE\n");
	    break;
	case AUDIT_BPRM_FCAPS: /* Inf. about fcaps increasing perms: 1321 */
	case AUDIT_CAPSET: /* sys_capset recort: 1322 */
	case AUDIT_MMAP: /* mmap: 1323 */
	case AUDIT_NETFILTER_PKT: /* packets traversing netfilter: 1324 */
	case AUDIT_NETFILTER_CFG: /* nefilter chaim moddifications: 1325 */
	case AUDIT_SECCOMP: /* secure computing event: 1326 */
	    verbose_print(&reply);
	    break;
	case AUDIT_PROCTITLE: /* proctitle emit 1327 */
	    rc = msg_proctitle(reply.message, buf);
	    if (rc < 0) {
		printf("\tPROCTITLE= NOMATCH\n\t");
		verbose_print(&reply);
	    } else {
		printf("\tPROCTITLE=%s\n", buf);
	    }
	    // verbose_print(&reply);
	    break;
	case AUDIT_FEATURE_CHANGE:/* audit log listing feature changes: 1328 */
	case AUDIT_REPLACE: /* Replace auditd if this packet unanswerd: 1329 */
	case AUDIT_KERN_MODULE:	/* Kernel Module events: 1330 */
	case AUDIT_FANOTIFY: /* Fanotify access decision: 1331 */
	case AUDIT_TIME_INJOFFSET: /* Timekeeping offset injected: 1332 */
	case AUDIT_TIME_ADJNTPVAL: /* NTP value adjustment: 1333  */
	    verbose_print(&reply);
	    break;
	default:
	    printf("Untracked event: Type = %s %x\n", audit_msg_type_to_name(reply.type),reply.type);
	    break;
	}
	fflush(stdout);
    }

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
