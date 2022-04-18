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

#define MQTT_HEADER_SIZE	2
#define MQTT_STATE_NORMAL		0
#define MQTT_STATE_START		0
#define MQTT_STATE_WAIT_FOR_LENFIELD	1
#define MQTT_STATE_RECEIVED_PACKET	2
#define MQTT_STATE_RECEIVING_PACKET	3

#define BSIZE	256
struct constate {
    int		live;	/* 1 if it must be taken care */
    int		rc;	/* return code of read */
    int		fd;
    uint16_t	pos;
    uint16_t	len;
    uint8_t	mqtt_cmd;
    uint32_t	mqtt_plen;
    uint8_t	mqtt_state;
    uint16_t	mqtt_rem;	/* remain of bytes */
    uint8_t	mqtt_pos;
    uint8_t	buf[BSIZE];
};

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
    default: strcmd = "UNKNOWN"; break;
    }
    return strcmd;
}

static void
__mqtt_event(uint8_t cmd, uint32_t len)
{
    fprintf(stderr, "CMD=%s(0x%x) LEN=%d\n",
	    cmd_string(cmd&0xf0), cmd, len);
}

static int
__mqtt_varint(struct constate *csp, uint32_t *ip)
{
    uint32_t	multi = 1;
    uint32_t	ival = 0;
    uint8_t	bval;
    int		i, cnt = 0;
    if (csp->mqtt_rem == 0) {
	return MQTT_STATE_WAIT_FOR_LENFIELD;
    }
    for (i = 0; i < 4; i++) {
	cnt++;
	bval = csp->buf[csp->mqtt_pos + i];
	ival += (bval&0x7f) * multi;
	multi *= 0x80;
	if (bval & 0x80) {
	    if (csp->mqtt_rem <= i + 1) {
		return MQTT_STATE_WAIT_FOR_LENFIELD;
	    }
	} else {
	    goto ext;
	}
    }
ext:
    csp->mqtt_pos += cnt;
    csp->mqtt_rem -= cnt;
    *ip = ival;
    return MQTT_STATE_NORMAL;
}

static void
__mqtt_protocol(int fd, struct constate *csp,
		ssize_t (*rfunc)(int fd, void *buf, size_t))
{
    int	rc;
    fprintf(stderr, "    %s:-----\n", __func__);
    csp->rc = rfunc(fd, csp->buf, BSIZE);
    fprintf(stderr, "\trc=%d\n", csp->rc);
    if (csp->rc < 0) {
	// perror("read:");
	return;
    }
    csp->len += csp->rc;
    csp->pos = 0;
    csp->mqtt_rem = csp->len;
    switch (csp->mqtt_state) {
    case MQTT_STATE_START:
	csp->len = csp->rc; /* reset */
	csp->mqtt_cmd = csp->buf[csp->pos];
	csp->mqtt_pos = 1;
	--csp->mqtt_rem;
	/* fall through */
    case MQTT_STATE_WAIT_FOR_LENFIELD:
	rc = __mqtt_varint(csp, &csp->mqtt_plen);
	if (rc == MQTT_STATE_WAIT_FOR_LENFIELD) {
	    csp->mqtt_state = MQTT_STATE_WAIT_FOR_LENFIELD;
	    return;
	} else {
	}
	/* fall through */
    case MQTT_STATE_RECEIVING_PACKET:
	break;
    case MQTT_STATE_RECEIVED_PACKET:
	break;
    }
    fprintf(stderr, "\tmqtt_plen=%d state=%d len(%d)\n", csp->mqtt_plen, csp->mqtt_state, csp->len);
    if ((csp->mqtt_plen + MQTT_HEADER_SIZE) == csp->len) {
	/* exact mqtt packet received */
	csp->mqtt_state = MQTT_STATE_RECEIVED_PACKET;
	__mqtt_event(csp->mqtt_cmd, csp->mqtt_plen);
	return;
    } else if ((csp->mqtt_plen + MQTT_HEADER_SIZE) > csp->len) {
	fprintf(stderr, "incomplete PACKET received\n");
	csp->mqtt_state = MQTT_STATE_RECEIVING_PACKET;
	return; 
    } else {
	/* */
	fprintf(stderr, "Next PACKET !!!\n");
    }
    fprintf(stderr, "YI 2\n");
    /* more MQTT packet arrives */
}
