/*
 *	This is an adhoc test program to understand seccomp.
 *						2021/10/01
 *	Testing notification with string argument and continue
 *	The mkdir() in glibc 2.10 and older version uses the mkdir()
 *	syscall, but later versionws uses mkdirat() syscall.
 */
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
    int rc = -1;
    int	pid;
    int fd, status;
    char	*libname;
    int	mem;
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

    printf("Testing notify the mkdir() glibc impemented by mkdirat() syscall\n");

    /*
     * seccomp_rule_add:
     *	When getpid system call is issued, its notification message is receivied.
     */
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(mkdirat), 0);
    printf("rule_add mkdirat rc = %d\n", rc);
    if (rc < 0) goto err;
    rc = seccomp_load(ctx);
    if (rc < 0) goto err;

    fd = seccomp_notify_fd(ctx);
    if (fd < 0) goto err;

    pid = fork();
    if (pid == 0) {
	/* child process */
	pid_t pid;
	int	rc;
	char	buf[20];
	memset(buf, 0, sizeof(buf));
	pid = getpid();
	strcpy(buf, "/tmp/");
	snprintf(&buf[5], 15, "%d", pid);
	printf("child: mkdir %s\n", buf);
	rc = mkdir(buf, 0774);
	printf("child:  rc = %d\n", rc);
	printf("child: rmdir %s\n", buf);
	rc = rmdir(buf);
	printf("child:  rc = %d\n", rc);
	printf("child: going to exit\n");
	exit(0);
    }
    /* parent process */
    rc = seccomp_notify_alloc(&req, &resp);
    if (rc) goto err;
    printf("waiting for nofification\n");
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
    resp->id = req->id;
    resp->error = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    printf("req->data.nr(%d) __NR_mkdirat(%d)\n", req->data.nr, __NR_mkdirat);
    if (req->data.nr == __NR_mkdirat) {
      if (lseek(mem, req->data.args[1], SEEK_SET) < 0) {
	printf("Cannot lseek to 0x%llx\n", req->data.args[1]);
      } else {
	char	buf[128];
	memset(buf, 0, sizeof(buf));
	read(mem, buf, 128);
	printf("args[1] = %s\n", buf);
      }
#if defined(__i386)
      /* mkdir syscall still exists in x86 Linux 5.XX. */
    } else if (req->data.nr == __NR_mkdir) {
      if (lseek(mem, req->data.args[0], SEEK_SET) < 0) {
	printf("Cannot lseek to 0x%llx\n", req->data.args[0]);
      } else {
	char	buf[128];
	memset(buf, 0, sizeof(buf));
	read(mem, buf, 128);
	printf("args[1] = %s\n", buf);
      }
    }
#else
    }
#endif /* x86 */
    printf("going to close mem(%d)\n", mem);
    close(mem);
    printf("done\n");
    printf("notify_respond\n");
    rc = seccomp_notify_respond(fd, resp);
    printf(" done\n");
    libname="seccomp_notify_respond";
    if (rc) goto err;
    seccomp_notify_free(req, resp);
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
