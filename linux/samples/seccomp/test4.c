#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <seccomp.h>

#define BUF_SIZE    256
char path[PATH_MAX];

int main(int argc, char *argv[])
{
    int rc = -1, i;
    int	ppid, pid;
    int fd, status;
    char	*libname;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    scmp_filter_ctx ctx;
    struct scmp_arg_cmp arg_cmp[] = { SCMP_A0(SCMP_CMP_EQ, 2) };
    unsigned char buf[BUF_SIZE];

    ppid = getpid();
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
//    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(write), 0);
//    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(read), 0);
//    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 0);
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(creat), 0);
    if (rc < 0) goto err;
    printf("Notify open syscall\n");
    rc = seccomp_load(ctx);
    if (rc < 0) goto err;

    fd = seccomp_notify_fd(ctx);
    if (fd < 0) goto err;

    pid = fork();
    if (pid == 0) {
	/* child process */
	pid_t pid;
	int	rc, fd;
	char	buf[11];
//	pid = getpid();
//	printf("pid = %d\n", pid);
#if 0
	rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 0);
	printf("open rule rc = %d\n", rc);
	rc = seccomp_load(ctx);
	printf("secomp_load rc = %d\n", rc);
	fd = open("/tmp/123", O_RDONLY);
	printf("fd = %d\n", fd);
	read(fd, buf, 10);
	buf[10] = 0;
	printf("data = %s\n", buf);
#endif
//#if 0
	fd = creat("/tmp/123", O_CREAT|O_WRONLY);
	printf("fd = %d\n", fd);
	strcpy(buf, "hello\n");
	write(fd, buf, 6);
	printf("write: %s\n", buf);
//#endif
	if (fd >= 0) {
	    rc = close(fd);
	    printf("rc = %d\n", rc);
	}
	sleep(2);
	exit(0);
    }
    /* parent process */
    rc = seccomp_notify_alloc(&req, &resp);
    if (rc) goto err;

    for (i = 0; i < 1; i++) {
	int	mem;
	printf("waiting for nofification (%d)\n", i);
	rc = seccomp_notify_receive(fd, req);
	printf("rc = %d\n", rc);
	libname="seccomp_notify_receive";
	if (rc) goto err;
	rc = seccomp_notify_id_valid(fd, req->id);
	libname="seccomp_notify_id_valid";
	if (rc) goto err;
	printf("req->pid = %d, nr = %d, arch = 0x%x, args[0] = 0x%llx, args[1] = 0x%llx\n",
	       req->pid, req->data.nr, req->data.arch,
	       req->data.args[0], req->data.args[1]);
	snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
	printf("path = %s\n", path);
	mem = open(path, O_RDONLY);
	if (mem < 0) {
	    perror("open memory");
	}
	printf("mem = %d\n", mem);
	switch (req->data.nr) {
	case __NR_getpid:
	    resp->val = -pid;
	    break;
	case __NR_open:
	    break;
	case __NR_creat:
	{
	    if (lseek(mem, req->data.args[0], SEEK_SET) < 0) {
		printf("Cannot lseek to 0x%llx\n", req->data.args[0]);
	    } else {
		char	buf[128];
		memset(buf, 0, sizeof(buf));
		read(mem, buf, 128);
		printf("args[1] = %s\n", buf);
	    }
	    break;
	}
	    break;
	case __NR_write:
	{
	    if (lseek(mem, req->data.args[1], SEEK_SET) < 0) {
		printf("Cannot lseek to 0x%llx\n", req->data.args[1]);
	    } else {
		char	buf[128];
		memset(buf, 0, sizeof(buf));
		read(mem, buf, 128);
		printf("args[1] = %s\n", buf);
	    }
	    break;
	}
	case __NR_close:
	    printf("close system call issued\n");
	    break;
	default:
	    rc = -999;
	    goto err;
	}
	printf("going to close mem(%d)\n", mem);
	close(mem);
	printf("done\n");
	resp->id = req->id;
	resp->error = 0;
	resp->flags = 0;
	printf("notify_respond\n");
	rc = seccomp_notify_respond(fd, resp);
	printf(" done\n");
	libname="seccomp_notify_respond";
	if (rc) goto err;
    }
out:
    printf("waiting for exiting pid(%d)\n", pid);
    if (waitpid(pid, &status, 0) != pid) {
	rc = -3;
	goto err;
    }
    seccomp_release(ctx);
    return -rc;
err:
    printf("seccomp ERROR: %s rc = %d\n", libname,  rc);
    perror("seccomp");
    goto out;
}
