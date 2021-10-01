/*
 *	This is an adhoc test program to understand seccomp.
 *						2021/10/01
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
#include <pthread.h>

#define BUF_SIZE    256
char path[PATH_MAX];

scmp_filter_ctx ctx;
int	fd;
pthread_mutex_t	mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t	cnd_start = PTHREAD_COND_INITIALIZER;
pthread_cond_t	cnd_stop = PTHREAD_COND_INITIALIZER;

void *
controller(void *arg)
{
    int	rc, i;
    char	*libname;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;

    printf("%s: Controller thread\n", __func__);
    pthread_mutex_lock(&mutex);
    printf("%s: Starting fd = %d\n", __func__, fd);

#define ITER	4
    for (i = 0; i < ITER; i++) {
	int	mem;
	rc = seccomp_notify_alloc(&req, &resp);
	libname="seccomp_notify_alloc";
	if (rc) goto err;
	printf("%s: waiting for nofification (%d)\n", __func__, i);
	rc = seccomp_notify_receive(fd, req);
	printf("%s: rc = %d\n", __func__, rc);
	libname="seccomp_notify_receive";
	if (rc) goto err;
	rc = seccomp_notify_id_valid(fd, req->id);
	libname="seccomp_notify_id_valid";
	if (rc) goto err;
	printf("%s: req->pid = %d, nr = %d, arch = 0x%x, args[0] = 0x%llx, args[1] = 0x%llx\n",
	       __func__, req->pid, req->data.nr, req->data.arch,
	       req->data.args[0], req->data.args[1]);
	snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
	printf("%s: path = %s\n", __func__, path);
	mem = open(path, O_RDONLY);
	if (mem < 0) {
	    perror("open memory");
	}
	printf("mem = %d\n", mem);
	switch (req->data.nr) {
	case __NR_getpid:
	    printf("%s: getpid\n", __func__);
	    resp->val = -123;
	    break;
	case __NR_open:
	{
	    printf("%s: open\n", __func__);
	    if (lseek(mem, req->data.args[0], SEEK_SET) < 0) {
		printf("%s: Cannot lseek to 0x%llx\n", __func__, req->data.args[0]);
	    } else {
		char	buf[128];
		memset(buf, 0, sizeof(buf));
		read(mem, buf, 128);
		printf("args[0] = %s\n", buf);
	    }
	    break;
	}
	case __NR_close:
	    printf("%s: close\n", __func__);
	    break;
	case __NR_exit:
	    printf("%s: close\n", __func__);
	    break;
	default:
	    printf("%s: NR = %d\n", __func__, req->data.nr);
	    rc = -999;
	    goto err;
	}
	printf("%s: going to close mem(%d)\n", __func__, mem);
	close(mem);
	printf("%s: done\n", __func__);
	resp->id = req->id;
	resp->error = 0;
	resp->flags = 0;
	printf("%s: notify_respond\n", __func__);
	rc = seccomp_notify_respond(fd, resp);
	printf("%s: done\n", __func__);
	libname="seccomp_notify_respond";
	if (rc) goto err;
	seccomp_notify_free(req, resp);
    }
out:
    pthread_mutex_unlock(&mutex);
    return NULL;
err:
    printf("%s: seccomp ERROR: %s rc = %d\n", __func__, libname,  rc);
    perror("seccomp");
    goto out;
}

/*
 *	The open syscall should be captured, but NOT !!!
 *	The exit syscall hangs on a child process !!!
 *	The child process issue the following sequence of syscalls:
 *		getpid(), getpid(), open(), read(), close(), exit()
 *	The main program adds compsec rules for getpid(), open(), and exit() syscalls.
 *	The controller tries to receive three notifications, but only two notifications
 *	are received, i.e., getpid() and getpid().
 *	The open() syscall cannot be captured.
 */
int main(int argc, char *argv[])
{
    int rc = -1, i;
    int	ppid, pid;
    int status;
    pthread_t	cntrl_thread;
    char	*libname;
    struct scmp_arg_cmp arg_cmp[] = { SCMP_A0(SCMP_CMP_EQ, 2) };
    unsigned char buf[BUF_SIZE];

    pthread_mutex_lock(&mutex);
    rc = pthread_create(&cntrl_thread, NULL, controller, NULL);
    ppid = getpid();
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    libname = "seccomp_init";
    if (ctx == NULL) goto err;
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(getpid), 0);
    libname = "seccomp_rule_add getpid";
    if (rc < 0) goto err;
    printf("open syscall = %d\n", SCMP_SYS(open));
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 0);
    libname = "seccomp_rule_add open";
    if (rc < 0) goto err;
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(close), 0);
    libname = "seccomp_rule_add close";
    if (rc < 0) goto err;
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(exit), 0);
    libname = "seccomp_rule_add exit";
    if (rc < 0) goto err;
    printf("main: Notify getpid(), open(), close(), and exit() syscall\n");
    rc = seccomp_load(ctx);
    libname = "seccomp_load";
    if (rc < 0) goto err;

    fd = seccomp_notify_fd(ctx);
    libname = "seccomp_notify_fd";
    if (fd < 0) goto err;

    pthread_mutex_unlock(&mutex);
    pid = fork();
    if (pid == 0) {
	/* child process */
	pid_t pid;
	int	rc, fd;
	char	buf[11];
	printf("child: going to issue getpid()\n");
	pid = getpid();
	printf("child: pid = %d\n", pid);

	printf("child: 2nd going to issue getpid()\n");
	pid = getpid();
	printf("child: pid = %d\n", pid);

	printf("child: going to issue open()\n");
	fd = open("/tmp/123", O_RDONLY);
	printf("child: fd = %d\n", fd);
	read(fd, buf, 10);
	buf[10] = 0;
	printf("child: data = %s\n", buf);
	if (fd >= 0) {
	    rc = close(fd);
	    printf("child: rc = %d\n", rc);
	}
	sleep(1);
	printf("child: going to issue exit()\n");
	exit(0);
    }
    /* parent process */
out:
    printf("main: waiting for exiting pid(%d)\n", pid);
    if (waitpid(pid, &status, 0) != pid) {
	printf("main: waitpid ??\n");
	return -3;
    }
    printf("main: waiting for exiting controller\n");
    pthread_mutex_lock(&mutex);
    printf("main: going to seccomp_release\n");
    seccomp_release(ctx);
    return 0;
err:
    printf("seccomp ERROR: %s rc = %d\n", libname,  rc);
    perror("seccomp");
    goto out;
}
