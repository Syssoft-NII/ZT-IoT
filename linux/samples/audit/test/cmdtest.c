#include <stdio.h>

extern int	exec_cmd(char *cmd, char **argv, char *header, char *msg);
char	*argv[5];
int
main()
{
    char	*cmd = "/usr/local/bin/mosquitto_pub";
    char	*header = "topic/test";
    char	*msg;
    argv[0] = "mosquitto_pub";
    argv[1] = "-t";
    argv[2] = header;
    argv[3] = "-l";
    msg = "message is here";
    exec_cmd(cmd, argv, header, msg);
}
