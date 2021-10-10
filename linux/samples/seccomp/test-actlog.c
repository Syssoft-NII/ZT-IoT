/*
 *	This is an adhoc test program to understand seccomp.
 *						2021/10/01
 *	This program does not run
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

scmp_filter_ctx ctx;
int	fd;

int main(int argc, char *argv[])
{
    int rc = -1;
    int	pid;
    int status;
    char	*libname;

    ctx = seccomp_init(SCMP_ACT_LOG);
    libname = "seccomp_init";
    if (ctx == NULL) goto err;
    rc = seccomp_load(ctx);
    libname = "seccomp_load";
    if (rc < 0) goto err;

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
    printf("main: going to seccomp_release\n");
    seccomp_release(ctx);
    return 0;
err:
    printf("seccomp ERROR: %s rc = %d\n", libname,  rc);
    perror("seccomp");
    goto out;
}
