/*
 *	This is an adhoc test program to understand seccomp.
 *						2021/10/01
 *				yutaka_ishikawa@nii.ac.jp
 *	Testing a notify capability using getpid() syscall
 *	Usage:
 *	./test3
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <seccomp.h>

#define BUF_SIZE    256

int main(int argc, char *argv[])
{
    int rc = -1;
    int	pid;
    int fd, status;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    scmp_filter_ctx ctx;

    /*
     * default action
     */
    /*
     *	The argument of seccomp_init() is default action:
     *	SCMP_ACT_KILL, SCMP_ACT_KILL_PROCESS, SCMP_ACT_TRAP,
     *	SCMP_ACT_ERRNO(uint16_t errno), SCMP_ACT_TRACE(uint16_t msg_num),
     *	SCMP_ACT_LOG, SCMP_ACT_ALLOW, SCMP_ACT_NOTIFY
     */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) goto err;

    /*
     * seccomp_rule_add:
     *	When getpid system call is issued, its notification message is receivied.
     */
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(getpid), 0);
    if (rc < 0) goto err;
    printf("Testing notify the getpid() syscall.\n"
	   "The return value is the negative of pid\n");
    rc = seccomp_load(ctx);
    if (rc < 0) goto err;

    fd = seccomp_notify_fd(ctx);
    if (fd < 0) goto err;

    pid = fork();
    if (pid == 0) {
	pid_t pid = getpid();
	printf("pid = %d\n", pid);
	/* child process */
	exit(0);
    }
    /* parent process */
    rc = seccomp_notify_alloc(&req, &resp);
    if (rc) goto err;
    rc = seccomp_notify_receive(fd, req);
    if (rc) goto err;
    if (req->data.nr != __NR_getpid) {
	rc = -999;
	goto err;
    }
    rc = seccomp_notify_id_valid(fd, req->id);
    if (rc) goto err;
    resp->id = req->id;
    resp->val = -pid;
    resp->error = 0;
    resp->flags = 0;
    rc = seccomp_notify_respond(fd, resp);
    if (rc) goto err;
    if (waitpid(pid, &status, 0) != pid) {
	rc = -3;
	goto err;
    }
out:
    seccomp_release(ctx);
    return -rc;
err:
    printf("seccomp ERROR: rc = %d\n", rc);
    goto out;
}
