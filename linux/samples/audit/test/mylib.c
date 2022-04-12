#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static
int setup_childpipe(int *to, int *from)
{
    int	cc, i;
    close(0); //close stdin
    cc = dup(to[0]); //connect pipe
    if (cc != 0) goto err_return;
    close(1); //close stdout
    cc = dup(from[1]); //connect pipe
    if (cc != 1) goto err_return;
    /* other file descriptors are closed */
    for (i = 3; i < 10; i++) {
	close(i);
    }
    return 0;
err_return:
    return -1;
}

int
exec_cmd(char *cmd, char **argv, char *header, char *msg)
{
    int	to_child[2], from_child[2];
    int	chpid, cc;
    int	rfd;
    FILE	*wfp;
    
    if (pipe(to_child) == -1 || pipe(from_child) == -1) {
	perror("Creating pipe: failed");
	return -1;
    }
    if ((chpid = fork()) == 0) {
	/* child */
	printf("Child cmd=%s\n", cmd); fflush(stdout);
	if (setup_childpipe(to_child, from_child) < 0) {
	    exit(-1);
	}
	cc = execv(cmd, argv);
	if (cc < 0) {
	    fprintf(stderr, "Cannot exec \"%s\"\n", cmd);
	    perror("");
	    exit(-1);
	}
    } else if (chpid < 0) {
	perror("Creating pipe: failed");
	return -1;
    }
    /* parent */
    rfd = from_child[0]; close(from_child[1]);
    wfp = fdopen(to_child[1], "w"); close(to_child[0]);
    fputs(msg, wfp);
    fflush(wfp); fclose(wfp);
    close(rfd);
    waitpid(chpid, 0, 0);
    return 0;
}
