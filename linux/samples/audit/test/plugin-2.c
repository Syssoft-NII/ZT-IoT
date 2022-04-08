#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "libaudit.h"
#include "auparse.h"
#include "sysname.h"

#define PARAM_TYPE		0
#define PARAM_SYSCALL_ARCH	1
#define PARAM_SYSCALL_NUM	2
#define PARAM_SYSCALL_SUCCESS	3
#define PARAM_SYSCALL_EXIT	4
#define PARAM_SYSCALL_A0	5
#define PARAM_SYSCALL_A1	6
#define PARAM_SYSCALL_A2	7
#define PARAM_SYSCALL_A3	8
#define PARAM_SYSCALL_ITEMS	9
#define PARAM_SYSCALL_PPID	10
#define PARAM_SYSCALL_PID	11
#define PARAM_SYSCALL_AUID	12
#define PARAM_SYSCALL_UID	13
#define PARAM_SYSCALL_GID	14
#define PARAM_SYSCALL_EUID	15
#define PARAM_SYSCALL_SUID	16
#define PARAM_SYSCALL_FSUID	17
#define PARAM_SYSCALL_EGID	18
#define PARAM_SYSCALL_SGID	19
#define PARAM_SYSCALL_FSGID	20
#define PARAM_SYSCALL_TTY	21
#define PARAM_SYSCALL_SES	22
#define PARAM_SYSCALL_COMM	23
#define PARAM_SYSCALL_EXE	24
#define PARAM_SYSCALL_SUBJ	25
#define PARAM_SYSCALL_KEY	26
#define PARAM_MMAP_FD		1
#define PARAM_MMAP_FLAGS	2
#define PARAM_PATH_PATH		2

#define MAX_ARGS	16
#define MAX_PARAMS	48
const char	*params_syscall[MAX_PARAMS];
const char	*params_mmap[MAX_PARAMS];
const char	*params_path[MAX_PARAMS];
char	proctitle[MAX_AUDIT_MESSAGE_LENGTH];
const char	*cwd, *path;

pid_t	mypid;
long	count;

void cleanup_params(const char **area)
{
    int	i;
    for (i = 0; i < MAX_PARAMS; i++) {
	area[i] = NULL;
    }
}

void cleanup()
{
    cwd = 0; proctitle[0] = 0;  path = 0;
    cleanup_params(params_syscall);
    cleanup_params(params_mmap);
    cleanup_params(params_path);
}

char	*args[MAX_ARGS];

#define LOG_FILE	"/tmp/LOG_AUDIT"
char	combuf[MAX_AUDIT_MESSAGE_LENGTH];
auparse_state_t	*au;

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

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig)
{
    printf("SIGHUP is catched\n");
    exit(-1);
}

static void
handle_event(auparse_state_t *au,
	     auparse_cb_event_t cb_event_type, void *user_data)
{
    int		nrec, tot_args, syscall, i;

    if (cb_event_type != AUPARSE_CB_EVENT_READY)
	return;
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
	    path = params_path[PARAM_PATH_PATH]
		= auparse_get_field_str(au);
	    // printf("\tPATH=%s\n", params_path[PARAM_PATH_PATH]);
	    break;
	case AUDIT_PROCTITLE:
	    auparse_goto_field_num(au, 1);
	    cp = auparse_get_field_str(au);
	    hex2ascii(cp, proctitle);
	    //printf("\tPROCTITLE=%s\n", proctitle);
	    break;
	case AUDIT_CWD:
	    auparse_goto_field_num(au, 1);
	    cwd = auparse_get_field_str(au);
	    //printf("\tCWD=%s\n", cwd);
	    break;
	case AUDIT_EXECVE:
	{
	    int	k, argc;
	    const char	*str_argc, **str_arg;
	    auparse_goto_field_num(au, 1);
	    str_argc = auparse_get_field_str(au);
	    argc = atoi(str_argc);
	    str_arg = malloc(sizeof(char*)*argc);
	    for (k = 0; k < argc; k++) {
		auparse_goto_field_num(au, k + 2);
		str_arg[k] = auparse_get_field_str(au);
	    }
	    printf("\tEXECVE=%s, argc = %d(%s), ", cp, argc, str_argc);
	    for (k = 0; k < argc; k++) {
		printf("%s, ", str_arg[k]);
	    }
	    printf("\n");
	    // printf("\t\tRAWTEXT=\"%s\"\n", auparse_get_record_text(au));
	    free(str_arg);
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
	default:
	    printf("\tUNPROCESSING type(%d)(%s) recordpos(%d) %s #fields(%d)==>",
		   type, cp, i, auparse_interpret_field(au), fnum);
	    for (j = 0; j < fnum; j++) {
		printf("\t%s(%d) ", auparse_get_field_str(au), j);
		auparse_next_field(au);
	    }
	    printf("\n");
	    printf("\t\tRAWTEXT=\"%s\"\n", auparse_get_record_text(au));
	}
    }
    printf("EVENT(%ld): nrec(%d)\n", count, nrec);
    if (syscall != -1) {
	int	j;
	printf("\ttopic=/IoT/XXX/%s/audit =",
	       params_syscall[PARAM_SYSCALL_PID]);
	printf(" ppid=%s uid=%s gid=%s "
	       "SYSCALL=%s (%d) success(%s) exit(%s) ",
	       params_syscall[PARAM_SYSCALL_PPID],
	       params_syscall[PARAM_SYSCALL_UID],
	       params_syscall[PARAM_SYSCALL_GID],
	       sysname[syscall], syscall,
	       params_syscall[PARAM_SYSCALL_SUCCESS],
	       params_syscall[PARAM_SYSCALL_EXIT]);
	for (j = 0; j < 4; j++) {
	    printf(" arg%d(%s)", j, params_syscall[j+PARAM_SYSCALL_A0]);
	}
	if (path) { printf(" path=%s", path); }
	printf(" exec=%s", params_syscall[PARAM_SYSCALL_EXE]);
	//if (proctitle[0] != 0) { printf(" proctitle=%s", proctitle); }
	printf("\n");
    } else {
	printf("syscall = -1\n");
    }
ext:
    return;
}

int
main(int argc, char **argv)
{
    FILE	*fin, *fout;
    ssize_t	len;
    struct sigaction sa;

    count = 100;
    mypid = getpid();
    /* Register sighandlers */
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    /* Set handler for the ones we care about */
    sa.sa_handler = term_handler;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = hup_handler;
    sigaction(SIGHUP, &sa, NULL);

    fout = fopen(LOG_FILE, "w");
    if (fout == NULL) {
	fprintf(stderr, "Cannot open file %s\n", LOG_FILE);
	return -1;
    }
    fin = fdopen(0, "r");
    if (fin == NULL) {
	fprintf(fout, "Cannot open file %s\n", LOG_FILE);
	return -1;
    }
    stdout = fout;
    /* Initialize the auparse library */
    au = auparse_init(AUSOURCE_FEED, 0);
    if (au == NULL) {
	printf("%s is exiting due to auparse init errors\n", argv[0]);
	return -1;
    }
    auparse_set_eoe_timeout(2);
    auparse_add_callback(au, handle_event, NULL, NULL);
    /**/
    printf("<%d>Now listing.....\n", mypid); fflush(stdout);
    while ((len = read(0, combuf, MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
	// printf("READ(%ld)==> %s<==READ\n", len, buf); fflush(stdout);
	auparse_feed(au, combuf, len);
	--count;
	if (count == 0) break;
    }
    printf("EXITING\n");
    fclose(fout); fclose(fin);
    return 0;
}
