#include <stdio.h>
#include <stdint.h>
#define MQTT_STATE_NORMAL		0
#define MQTT_STATE_WAIT_FOR_LENFIELD	1
#define MQTT_STATE_RECEIVE_PACKET	2
#define MQTT_STATE_RECEIVING_PACKET	3

#define BSIZE	256
struct constate {
    int		live;	/* 1 if it must be taken care */
    int		rc;	/* return code of read */
    int		fd;
    uint16_t	pos;
    uint16_t	len;
    uint8_t	mqtt_state;
    uint8_t	mqtt_cmd;
    uint16_t	mqtt_rem;	/* remain of bytes */
    uint8_t	mqtt_pos;
    uint8_t	buf[BSIZE];
};

static int
__mqtt_varint(struct constate *csp)
{
    uint32_t	multi = 1;
    uint32_t	ival = 0;
    uint8_t	bval;
    int		i, cnt = 0;
    if (csp->mqtt_rem == 0) {
	csp->mqtt_state = MQTT_STATE_WAIT_FOR_LENFIELD;
	return 0;
    }
    for (i = 0; i < 4; i++) {
	cnt++;
	bval = csp->buf[csp->mqtt_pos + i];
	ival += (bval&0x7f) * multi;
	multi *= 0x80;
	if (bval & 0x80) {
	    if (csp->mqtt_rem <= i + 1) {
		csp->mqtt_state = MQTT_STATE_WAIT_FOR_LENFIELD;
		return 0;
	    }
	} else {
	    csp->mqtt_state = MQTT_STATE_NORMAL;
	    goto ext;
	}
    }
ext:
    csp->pos += cnt;
    csp->mqtt_pos += cnt;
    csp->mqtt_rem -= cnt;
    return ival;
}

struct constate cstat;

void
check_varint(struct constate *csp)
{
    int	val;
    val = __mqtt_varint(csp);
    printf("pos(%d) mqtt_pos(%d) mqtt_rem(%d)\t",
	   csp->pos, csp->mqtt_pos, csp->mqtt_rem);
    if (csp->mqtt_state != MQTT_STATE_WAIT_FOR_LENFIELD) {
	printf("val = %d\n", val);
    } else {
	printf("WAIT FOR MORE BYTE\n");
    }
}

int
main()
{
    int		val;
    cstat.pos = 0; cstat.mqtt_pos = 0;
    cstat.len = cstat.mqtt_rem = 10;
    /* 1byte */
    cstat.buf[0] = 127;
    check_varint(&cstat);
    /* 2 byte */
    cstat.pos = 0; cstat.mqtt_pos = 0;
    cstat.len = cstat.mqtt_rem = 10;
    cstat.buf[0] = 0xFF; cstat.buf[1] = 0x7F;
    check_varint(&cstat);
    /* 3 byte */
    cstat.pos = 0; cstat.mqtt_pos = 0;
    cstat.len = cstat.mqtt_rem = 10;
    cstat.buf[0] = 0xFF; cstat.buf[1] = 0xFF; cstat.buf[2] = 0x7F;
    check_varint(&cstat);
    /* 4 byte */
    cstat.pos = 0; cstat.mqtt_pos = 0;
    cstat.len = cstat.mqtt_rem = 10;
    cstat.buf[0] = 0xFF; cstat.buf[1] = 0xFF; cstat.buf[2] = 0xFF;
    cstat.buf[3] = 0x7F;
    check_varint(&cstat);
    
    /* just one available */
    cstat.pos = 0; cstat.mqtt_pos = 0; cstat.mqtt_rem = 0;
    cstat.len = cstat.mqtt_rem = 1;
    check_varint(&cstat);

    /* two byte available */
    cstat.pos = 0; cstat.mqtt_pos = 0; cstat.mqtt_rem = 0;
    cstat.len = cstat.mqtt_rem = 2;
    check_varint(&cstat);

    cstat.pos = 0; cstat.mqtt_pos = 0; cstat.mqtt_rem = 0;
    cstat.len = cstat.mqtt_rem = 3;
    check_varint(&cstat);

    cstat.pos = 0; cstat.mqtt_pos = 0; cstat.mqtt_rem = 0;
    cstat.len = cstat.mqtt_rem = 4;
    check_varint(&cstat);
    return 0;
}
