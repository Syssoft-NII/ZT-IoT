#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libaudit.h>
#include <getopt.h>

int
main(int argc, char **argv)
{
    int	fd;
//    int		type = AUDIT_TRUSTED_APP; // does not work
//    int		type = AUDIT_USYS_CONFIG; // does not work
    int		type = AUDIT_USER_LOGIN;  // works
    char	*message;
    char	*hostname;
    char	*addr;
    char	*tty;
    int		result;
    int		rc, i;
    fd = audit_open();
    if (fd < 0) {
	perror("audit_open: ");
	exit(-1);
    }
    message = "this is a test";
    addr = 0; /* network address */
    tty = "mytty"; /* tty */
    result = 0; /* 1 success, 0 fail */
    for (i = 0; i < 3; i++) {
	rc = audit_log_user_message(fd, type, message, hostname, addr, tty, result);
	if (rc == -1) {
	    printf("audit_log_user_message() error\n");
	} else {
	    printf("sequence number = %d\n", rc);
	}
    }
    return 0;
}
