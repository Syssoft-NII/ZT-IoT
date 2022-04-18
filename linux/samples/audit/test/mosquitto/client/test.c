#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

struct mqtt_header {
    uint8_t	cmd; /* 0 */
    uint8_t	len; /* 1 */
};
struct mqtt_con {
    struct mqtt_header hdr;
    uint8_t	len[2]; /* 2: must be 4 */
    uint8_t	mqtt[4]; /* 3-6 */
    uint8_t	level; /* 7 */
    uint8_t	flags; /* 8 */
    uint8_t	keep_alive[2]; /* 9-10 */
};
struct mqtt_connack {
    struct mqtt_header hdr;
    uint8_t	ack_flags;
    uint8_t	retcode;
};
#define CON_CLEAN_SESSION	0x2
#define CON_WILL_FLAG	0x4
#define CON_WILL_QOS	0xc
#define CON_WILL_RETAIN	0x20
#define CON_PASWD_FLAG	0x40
#define CON_USERNAM_FLAG	0x80
/*
 * PUBLISH (where QoS > 0), PUBACK, PUBREC, PUBREL, PUBCOMP,
 * SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK has ID field in its header
 */
struct mqtt_id {
    uint8_t	id_msb;
    uint8_t	id_lsb;
};

/* Message types */
#define CMD_CONNECT 0x10U
#define CMD_CONNACK 0x20U
#define CMD_PUBLISH 0x30U
#define CMD_PUBACK 0x40U
#define CMD_PUBREC 0x50U
#define CMD_PUBREL 0x60U
#define CMD_PUBCOMP 0x70U
#define CMD_SUBSCRIBE 0x80U
#define CMD_SUBACK 0x90U
#define CMD_UNSUBSCRIBE 0xA0U
#define CMD_UNSUBACK 0xB0U
#define CMD_PINGREQ 0xC0U
#define CMD_PINGRESP 0xD0U
#define CMD_DISCONNECT 0xE0U
#define CMD_AUTH 0xF0U

const char *
cmd_string(unsigned int cmd)
{
    char	*strcmd;
    switch (cmd) {
    case CMD_CONNECT: strcmd = "CONNECT"; break;
    case CMD_CONNACK: strcmd = "CONNACK"; break;
    case CMD_PUBLISH: strcmd = "PUBLISH"; break;
    case CMD_PUBACK: strcmd = "PUBACK"; break;
    case CMD_PUBREC: strcmd = "PUBREC"; break;
    case CMD_PUBREL: strcmd = "PUBREL"; break;
    case CMD_SUBSCRIBE: strcmd = "SUBSCRIBE"; break;
    case CMD_SUBACK: strcmd = "SUBACK"; break;
    case CMD_UNSUBSCRIBE: strcmd = "UNSUBSCRIBE"; break;
    case CMD_UNSUBACK: strcmd = "UNSUBACK"; break;
    case CMD_PINGREQ: strcmd = "PINGREQ"; break;
    case CMD_PINGRESP: strcmd = "PINGRESP"; break;
    case CMD_DISCONNECT: strcmd = "DISCONNECT"; break;
    case CMD_AUTH: strcmd = "AUTH"; break;
    }
    return strcmd;
}


#define TCP_PORT	1983
#define HOST_NAME	"localhost"

static char *
ipaddr(char* addr)
{
    static char	buf[128];
    sprintf(buf, "%03d:%03d:%03d:%03d", addr[0], addr[1], addr[2], addr[3]);
    return buf;
}

#define BSIZE	128
unsigned char	buf[BSIZE];

void
con_show(struct mqtt_con* mqcon)
{
    printf("len(%d) %c%c%c%c\n",
	   mqcon->len[0] << 8 | mqcon->len[1],
	   mqcon->mqtt[0], mqcon->mqtt[1], mqcon->mqtt[2], mqcon->mqtt[3]);
    printf("level(%d) flags(0x%x) keep_alive(%d)\n",
	   mqcon->level, mqcon->flags,
	   mqcon->keep_alive[0] << 8 | mqcon->keep_alive[1]);
    if (mqcon->flags & CON_CLEAN_SESSION) {
	printf("CLEAN_SESSION ");
    }
    if (mqcon->flags & CON_WILL_FLAG) {
	printf("WILL_FLAG ");
    }
    printf("WILL_QOS(%d) ", (mqcon->flags & CON_WILL_QOS)>>3);
    if (mqcon->flags & CON_WILL_RETAIN) {
	printf("WILL_RETAIN ");
    }
    if (mqcon->flags & CON_PASWD_FLAG) {
	printf("PASSWARD ");
    }
    if (mqcon->flags & CON_USERNAM_FLAG) {
	printf("USERNAME ");
    }
    printf("\n");
}

void
server(int port)
{
    struct hostent	*hp;
    struct sockaddr_in	saddr_in;
    struct sockaddr_in	saddr_out;
    int			addrlen;
    int			sock;
    int			fd;
    ssize_t	len;
    int		i;
    int		flags;

    bzero((char*)&saddr_in, sizeof(saddr_in));
    saddr_in.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr_in.sin_family = AF_INET;
    saddr_in.sin_port = htons(port);
    printf("receiving from any host from port %d\n", port);
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	fprintf(stderr, "Cannot open a SOCK_DGRAM socket\n");
	exit(-1);
    }
    if (bind(sock, (struct sockaddr*) &saddr_in, sizeof(saddr_in)) < 0) {
	fprintf(stderr, "Cannot bind\n");
	perror(" ");
	exit(-1);
    }
    if (listen(sock, 10) < 0) {
	fprintf(stderr, "Listen error\n");
	exit(-1);
    }
    addrlen = sizeof(saddr_out);
    if ((fd = accept(sock, (struct sockaddr*) &saddr_out, &addrlen)) < 0) {
	fprintf(stderr, "Error\n");
	exit(-1);
    }
    printf("fd = %d sock = %d\n", fd, sock);
    
    len = read(fd, buf, BSIZE);
    printf("received length = %ld\n", len);
    printf("\t");
    for (i = 0; i < len; i++) {
	printf("0x%x[%d] ", buf[i], i);
    }
    printf("\n");
    printf("CMD(%x) = %s\n", buf[0], cmd_string(buf[0]));
    printf("length = %d\n", buf[1]);
    /* CONNECT payload */
    printf("length = %d must be 4\n", (buf[2] << 8) | buf[3]);
    printf("%c%c%c%c must be MQTT\n", buf[4], buf[5], buf[6], buf[7]);
    printf("level = %d must be 4\n", buf[8]);
    printf("flags = 0x%x (2=Will)\n", buf[9]);
    flags = buf[9];

    con_show((struct mqtt_con*) &buf[0]);

    /* CONNACK */
    {
	struct mqtt_connack connack;
	connack.hdr.cmd = CMD_CONNACK;
	connack.hdr.len = 2;
	connack.ack_flags = 0;
	connack.retcode = 0;
	len = write(fd, &connack, sizeof(connack));
	printf("Sending CONNACK size(%ld) len(%ld)\n", sizeof(connack), len);
    }

    /* SUBSCRIBE ? */
    len = read(fd, buf, BSIZE);
    printf("received length = %ld\n", len);
    printf("\t");
    for (i = 0; i < len; i++) {
	printf("0x%x[%d] ", buf[i], i);
    }
    printf("\n");
    if (buf[0] & 0xf0 == CMD_SUBSCRIBE) {
	printf("SUBSCRIBE\n");
    }
    close(fd); close(sock);
}

int
main(int argc, char **argv)
{
    char *host = HOST_NAME;
    int		port = TCP_PORT;
    char *msg;
    struct hostent	*hp;
    struct sockaddr_in	saddr_in;
    int			sock;

    server(1884);
#if 0
    bzero((char*)&saddr_in, sizeof(saddr_in));
    if ((hp = gethostbyname(host)) == NULL) {
	fprintf(stderr, "Canot obtain the host info\n");
	exit(-1);
    }
    bcopy(hp->h_addr, (char *)&saddr_in.sin_addr, hp->h_length);
    printf("IP address = %s\n", ipaddr((char *)&saddr_in.sin_addr));
    saddr_in.sin_family = AF_INET;
    saddr_in.sin_port = htons(port);
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	fprintf(stderr, "Cannot open a SOCK_DGRAM socket\n");
	exit(-1);
    }
    if (connect(sock, (struct sockaddr*) &saddr_in, sizeof(saddr_in)) < 0) {
        fprintf(stderr, "Client:Can't connect Inet socket.\n");
	perror("");
        close(sock);
        exit(-1) ;
    }
    msg = "Hello";
    write(sock, msg, strlen(msg) + 1);
#endif
}
