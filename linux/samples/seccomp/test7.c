/*
 *	This is an adhoc test program to understand seccomp.
 *						2021/10/01
 */
/*
 *	The exit() system call cannot be captured.
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

scmp_filter_ctx ctx;
int	fd;
pthread_mutex_t	mutex_start = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	mutex_stop = PTHREAD_MUTEX_INITIALIZER;

void *
controller(void *arg)
{
    int	rc, i;
    char	*libname;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;

    printf("%s: Controller thread\n", __func__);
    pthread_mutex_lock(&mutex_start);
    printf("%s: Starting fd = %d\n", __func__, fd);

    rc = seccomp_notify_alloc(&req, &resp);
    if (rc) goto err;

#define ITER 1
    for (i = 0; i < ITER; i++) {
	int	mem;
	printf("%s: waiting for nofification (%d)\n", __func__, i);
	rc = seccomp_notify_receive(fd, req);
	printf("%s: rc = %d\n", __func__, rc); fflush(stdout);
	libname="seccomp_notify_receive";
	if (rc) goto err;
	rc = seccomp_notify_id_valid(fd, req->id);
	libname="seccomp_notify_id_valid";
	if (rc) goto err;
	printf("%s: req->pid = %d, nr = %d, arch = 0x%x, args[0] = 0x%llx, args[1] = 0x%llx\n",
	       __func__, req->pid, req->data.nr, req->data.arch,
	       req->data.args[0], req->data.args[1]);
	resp->id = req->id;
	resp->error = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	switch (req->data.nr) {
	case __NR_exit:
	    printf("%s: exit\n", __func__);
	    break;
	default:
	    printf("%s: NR=%d\n", __func__, req->data.nr);
	    goto err;
	}
	printf("%s: notify_respond\n", __func__);
	rc = seccomp_notify_respond(fd, resp);
	printf("%s: done\n", __func__);
	libname="seccomp_notify_respond";
	if (rc) goto err;
    }
out:
    pthread_mutex_unlock(&mutex_stop);
    return NULL;
err:
    printf("%s: seccomp ERROR: %s rc = %d\n", __func__, libname,  rc);
    perror("seccomp");
    goto out;
}

int main(int argc, char *argv[])
{
    int rc = -1, i;
    int	ppid, pid;
    int status;
    pthread_t	cntrl_thread;
    char	*libname;

    pthread_mutex_lock(&mutex_start);
    pthread_mutex_lock(&mutex_stop);
    rc = pthread_create(&cntrl_thread, NULL, controller, NULL);
    ppid = getpid();
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    libname = "seccomp_init";
    if (ctx == NULL) goto err;
    printf("exit system call is %d\n", SCMP_SYS(exit));
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(exit), 0);
    libname = "seccomp_rule_add exit";
    if (rc < 0) goto err;
    printf("main: Notify exit() syscall\n");
    rc = seccomp_load(ctx);
    libname = "seccomp_load";
    if (rc < 0) goto err;

    fd = seccomp_notify_fd(ctx);
    libname = "seccomp_notify_fd";
    if (fd < 0) goto err;

    pthread_mutex_unlock(&mutex_start);
    pid = fork();
    if (pid == 0) {
	/* child process */
	pid_t pid;
	int	rc, fd;
	char	buf[11];
	printf("child: going to issue getpid()\n");
	pid = getpid();
	printf("child: pid = %d\n", pid);
	sleep(10);
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
    pthread_mutex_lock(&mutex_stop);
    printf("main: going to seccomp_release\n");
    seccomp_release(ctx);
    return 0;
err:
    printf("seccomp ERROR: %s rc = %d\n", libname,  rc);
    perror("seccomp");
    goto out;
}
