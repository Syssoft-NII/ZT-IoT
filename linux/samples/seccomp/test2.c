#include <stdio.h>
#include <fcntl.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BUF_SIZE    256

int main(int argc, char *argv[])
{
    int rc = -1;
    scmp_filter_ctx ctx;
    struct scmp_arg_cmp arg_cmp[] = { SCMP_A0(SCMP_CMP_EQ, 2) };
    int fd;
    unsigned char buf[BUF_SIZE];

    /*
     *	The argument of seccomp_init() is default action:
     *	SCMP_ACT_KILL, SCMP_ACT_KILL_PROCESS, SCMP_ACT_TRAP,
     *	SCMP_ACT_ERRNO(uint16_t errno), SCMP_ACT_TRACE(uint16_t msg_num),
     *	SCMP_ACT_LOG, SCMP_ACT_ALLOW, SCMP_ACT_NOTIFY
     */
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) goto err;

    /*
     * seccomp_rule_add(): see man page
     */
    if (argc == 1) {
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(123), SCMP_SYS(getpid), 0);
	if (rc < 0) goto err;
	printf("Disable getpid syscall\n");
    } else {
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
	if (rc < 0) goto err;
	printf("Enable getpid syscall\n");
    }
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    if (rc < 0) goto err;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if (rc < 0) goto err;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
            SCMP_CMP(0, SCMP_CMP_EQ, 1));
    if (rc < 0) goto err;
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    if (rc < 0) goto err;

    rc = seccomp_load(ctx);
    if (rc < 0) goto out;

    pid_t pid = getpid();
    printf("pid = %d\n", pid);

out:
    seccomp_release(ctx);
    return -rc;
err:
    printf("seccomp ERROR: rc = %d\n", rc);
    goto out;
}
