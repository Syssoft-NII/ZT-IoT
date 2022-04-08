#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "libaudit.h"
#include "auparse.h"

#define LOG_FILE	"/tmp/LOG_AUDIT"
char buf[MAX_AUDIT_MESSAGE_LENGTH];
auparse_state_t	*au;

/*
 * SIGTERM handler
 */
static void term_handler(int sig)
{
    printf("SIGTERM is catched\n");
    exit(-1);
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig)
{
    printf("SIGHUP is catched\n");
    exit(-1);
}


static void
dump_fields_of_record(auparse_state_t *au)
{
    printf("record type %d(%s) has %d fields\n", auparse_get_type(au),
	   audit_msg_type_to_name(auparse_get_type(au)),
	   auparse_get_num_fields(au));

    printf("line=%d file=%s\n", auparse_get_line_number(au),
	   auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");

    const au_event_t *e = auparse_get_timestamp(au);
    if (e == NULL) {
	printf("Error getting timestamp - aborting\n");
	return;
    }
    /* Note that e->sec can be treated as time_t data if you want
     * something a little more readable */
    printf("event time: %u.%u:%lu, host=%s\n", (unsigned)e->sec,
	   e->milli, e->serial, e->host ? e->host : "?");
    auparse_first_field(au);
    do {
	printf("field: %s=%s (%s)\n",
	       auparse_get_field_name(au),
	       auparse_get_field_str(au),
	       auparse_interpret_field(au));
    } while (auparse_next_field(au) > 0);
    printf("\n");
}

/* This function shows how to dump a whole event by iterating over records */
static void
dump_whole_event(auparse_state_t *au)
{
	auparse_first_record(au);
	do {
		printf("%s\n", auparse_get_record_text(au));
	} while (auparse_next_record(au) > 0);
	printf("\n");
}

/* This function shows how to dump a whole record's text */
static void
dump_whole_record(auparse_state_t *au)
{
    printf("%s: %s\n", audit_msg_type_to_name(auparse_get_type(au)),
	   auparse_get_record_text(au));
    printf("\n");
}


static void
handle_event(auparse_state_t *au,
	     auparse_cb_event_t cb_event_type, void *user_data)
{
    int type, num=0;

    printf("EVENT: %x\n", cb_event_type);
    if (cb_event_type != AUPARSE_CB_EVENT_READY)
	return;
    while (auparse_goto_record_num(au, num) > 0) {
	const char	*cp;
	int	fnum;
	type = auparse_get_type(au);
	cp = audit_msg_type_to_name(type);
	printf("\ttype(%d)(%s) num(%d) %s ", type, cp, num, auparse_interpret_field(au));
	fnum = auparse_get_num_fields(au);
	printf("filed_type(%d) field_name(%s) #fields(%d)\n", auparse_get_field_type(au), auparse_get_field_name(au), fnum);
	while (fnum-- > 0) {
	    printf("\t%s(%d) ", auparse_get_field_str(au), fnum);
	    auparse_next_field(au);
	}
	printf("\n");
	if (type == AUDIT_SYSCALL
	    || type == AUDIT_PATH) {
	    auparse_goto_field_num(au, 2);
	    printf("\t pos(2)=%s,  skip showing whole record\n", auparse_get_field_str(au));
	    num++;
	    continue;
	}
	/* Now we can branch based on what record type we find.
	   This is just a few suggestions, but it could be anything. */
	switch (type) {
	case AUDIT_USER_LOGIN: /* 1112 libaudit.h */
	case AUDIT_USER_LOGOUT: /* 1113 libaudit.h */
	    break;
	case AUDIT_AVC:		/* 1400 SE Linux avc denial or grant */
	    dump_fields_of_record(au);
	    break;
	case AUDIT_DAEMON_START: /* 1200 */
	case AUDIT_DAEMON_END: /* 1201 */
	case AUDIT_DAEMON_ABORT: /* 1202 */
	case AUDIT_DAEMON_CONFIG: /* 1203 */
	    dump_whole_record(au);
	    break;
	case AUDIT_SYSCALL:	/* 1300 <linux/audit.h> */
	    dump_whole_record(au);
	    break;
	case AUDIT_PATH:	/* 1302 */
	case AUDIT_IPC:	/* 1303 */
	case AUDIT_SOCKETCALL: /* 1304 */
	case AUDIT_CONFIG_CHANGE: /* 1305 */
	case AUDIT_SOCKADDR: /* 1306 */
	case AUDIT_PROCTITLE:	/* 1327 */
	    dump_whole_record(au);
	    break;
	case AUDIT_MAC_STATUS: /* 1404 changed enforcing,permmssive,off */
	    dump_whole_event(au); 
	    break;
	case AUDIT_ANOM_ABEND: /* 1701 process ended abnormally */
	default:
	    dump_whole_record(au);
	    break;
	}
	num++;
    }
}

int
main(int argc, char **argv)
{
    FILE	*fin, *fout;
    ssize_t	len;
    long	count = 100;
    struct sigaction sa;

    /* Register sighandlers */
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    /* Set handler for the ones we care about */
    sa.sa_handler = term_handler;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = hup_handler;
    sigaction(SIGHUP, &sa, NULL);

    fout = fopen(LOG_FILE, "w");
    if (fout == NULL) {
	fprintf(stderr, "Cannot open file %s\n", LOG_FILE);
	return -1;
    }
    fin = fdopen(0, "r");
    if (fin == NULL) {
	fprintf(fout, "Cannot open file %s\n", LOG_FILE);
	return -1;
    }
    stdout = fout;
    /* Initialize the auparse library */
    au = auparse_init(AUSOURCE_FEED, 0);
    if (au == NULL) {
	printf("%s is exiting due to auparse init errors\n", argv[0]);
	return -1;
    }
    auparse_set_eoe_timeout(2);
    auparse_add_callback(au, handle_event, NULL, NULL);
    /**/
    printf("Now listing...\n"); fflush(stdout);
    while ((len = read(0, buf, MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
#if 0
	if (auparse_feed_has_data(au)) {
	    printf("HAS_DATA\n");
	    auparse_feed_age_events(au);
	}
#endif
	printf("READ(%ld)==> %s<==READ\n", len, buf); fflush(stdout);
	auparse_feed(au, buf, len);
	--count;
	if (count == 0) break;
    }
    fclose(fout); fclose(fin);
    return 0;
}
