#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>

#define REG_SEQNUM	0
#define REG_SYSCALL	1
#define REG_PROCTITLE1	2
#define REG_PROCTITLE2	3
#define REG_PID		4
#define REG_FILEPATH	5
#define REG_MAX		6

static regex_t	preg_audit[REG_MAX];
static char	*regex_audit[REG_MAX+1] = {
//    "audit([0-9].*:\\([0-9].*\\)):",
    "audit(\\([0-9].*\\):\\([0-9].*\\)):",
    ".*syscall=\\([0-9].*\\) success",
    ".*proctitle=\\([0-9|A-F].*\\) ",
    ".*proctitle=\\(\".*\"\\)",
    ".* pid=\\([0-9].*\\) ",
    "item=\\([0-9].*\\) name=\"\\(.*\\)\" ",
    0
};


static char	*tmpbuf;
static size_t	tbsz;
static char	errbuf[1024];

static char
_h2a(char *p)
{
    int	i, v, val = 0;

    for (i = 0; i < 2; i++) {
	val = val * 16;
	v = *(p + i) - '0';
	if (v >= 0 && v <= 9) {
	    val += v;
	} else {
	    val += (*(p + i) - 'A' + 10);
	}
    }
    return val;
}

/* return value is "int" instead of size_t */
int
hex2ascii(char *hex, char *asc)
{
    int	idx = 0;
    size_t	sz = 0;
    while (*(hex+idx) != 0) {
	char	ch = _h2a(hex+idx);
	*asc++ = ch;
	if (ch == 0) goto ext;
	idx += 2;
	sz++;
    }
    *asc = 0;
ext:
    return sz;
}

void
regex_init(size_t bsz)
{
    int	rc, i;
    size_t	sz;
    tbsz = bsz;
    tmpbuf = malloc(bsz);
    if (tmpbuf == NULL) {
	fprintf(stderr, "Cannot allocate memory\n");
	exit(-1);
    }
    for (i = 0; i < REG_MAX; i++) {
	if ((rc = regcomp(&preg_audit[i], regex_audit[i], 0)) < 0) {
	    printf("compile error\n");
	    sz = regerror(rc, &preg_audit[i], errbuf, 1024);
	    printf("errbuf=%s\n", errbuf);
	}
    }
}

static int
regex_pattern0(regex_t *preg, char *msg, char *rslt1, char *rslt2)
{
    regmatch_t	pmatch[3];
    size_t	sz;
    int	rc;
    memset(pmatch, 0, sizeof(pmatch));
    if ((rc = regexec(preg, msg, 3, pmatch, 0)) < 0
	|| rc == REG_NOMATCH) {
	return -1;
    }
    /* 1st */
    sz = pmatch[1].rm_eo - pmatch[1].rm_so;
    strncpy(rslt1, &msg[pmatch[1].rm_so], sz);
    rslt1[sz] = 0;
    /* 2nd */
    sz = pmatch[2].rm_eo - pmatch[2].rm_so;
    strncpy(rslt2, &msg[pmatch[2].rm_so], sz);
    rslt2[sz] = 0;
    return 0;
}

static int
regex_pattern1(regex_t *preg, char *msg, long *rslt)
{
    regmatch_t	pmatch[2];
    size_t	sz;
    int	rc;
    memset(pmatch, 0, sizeof(pmatch));
    if ((rc = regexec(preg, msg, 2, pmatch, 0)) < 0
	|| rc == REG_NOMATCH) {
	return -1;
    }
    sz = pmatch[1].rm_eo - pmatch[1].rm_so;
    // printf("start=%d, end=%d, sz = %ld\n", pmatch[1].rm_so, pmatch[1].rm_eo, sz);
    
    strncpy(tmpbuf, &msg[pmatch[1].rm_so], sz);
    tmpbuf[sz] = 0;
    // printf("%s(%d,%d)\n", tmpbuf, pmatch[1].rm_so, pmatch[1].rm_eo);
    *rslt = atol(tmpbuf);
    return 0;
}

static int
regex_pattern2(regex_t *preg, char *msg, char *rslt)
{
    regmatch_t	pmatch[2];
    size_t	sz;
    int	rc;
    memset(pmatch, 0, sizeof(pmatch));
    if ((rc = regexec(preg, msg, 2, pmatch, 0)) < 0
	|| rc == REG_NOMATCH) {
	return -1;
    }
    sz = pmatch[1].rm_eo - pmatch[1].rm_so;
    // printf("start=%d, end=%d, sz = %ld\n", pmatch[1].rm_so, pmatch[1].rm_eo, sz);
    
    strncpy(rslt, &msg[pmatch[1].rm_so], sz);
    rslt[sz] = 0;
    // printf("%s(%d,%d)\n", tmpbuf, pmatch[1].rm_so, pmatch[1].rm_eo);
    return sz;
}

int
msg_seqnum(char *msg, long *seq, long *tm1, long *tm2)
{
    int	rc;
    char	*cp;
    char	buf1[1024], buf2[1024];
    
    // rc = regex_pattern1(&preg_audit[REG_SEQNUM], msg, rslt);
    rc = regex_pattern0(&preg_audit[REG_SEQNUM], msg, buf1, buf2);
    *seq = atol(buf2);
    if ((cp = index(buf1, '.')) == NULL) {
	/* no msec */
	*tm1 = atol(buf1);
	*tm2 = 0;
    } else {
	*cp = 0;
	*tm1 = atol(buf1); *tm2 = atol(cp + 1);
    }
    return rc;
}

int
msg_syscall(char *msg, long *rslt)
{
    int	rc;
    rc = regex_pattern1(&preg_audit[REG_SYSCALL], msg, rslt);
    return rc;
}


int
msg_pid(char *msg, long *rslt)
{
    int	rc;
    rc = regex_pattern1(&preg_audit[REG_PID], msg, rslt);
    return rc;
}

int
msg_proctitle(char *msg, char *rslt)
{
    int	rc;
    rc = regex_pattern2(&preg_audit[REG_PROCTITLE1], msg, rslt);
    if (rc < 0) {
	rc = regex_pattern2(&preg_audit[REG_PROCTITLE2], msg, rslt);
    }
    return rc;
}

int
msg_filepath(char *msg, long *item, char *path)
{
    int	rc;
    char buf1[1024];
    rc = regex_pattern0(&preg_audit[REG_FILEPATH], msg, buf1, path);
    *item = atol(buf1);
    return rc;
}
