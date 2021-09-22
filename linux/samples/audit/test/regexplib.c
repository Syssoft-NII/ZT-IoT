#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>

static regex_t	preg_seqnum;
static regex_t	preg_syscall;
static regex_t	preg_proctitle1;
static regex_t	preg_proctitle2;
static char	*regex_seqnum = "audit([0-9].*:\\([0-9].*\\)):";
//static char	*regex_seqnum = "audit(\\([0-9].*\\):\\([0-9].*\\)):";
static char	*regex_syscall = ".*syscall=\\([0-9].*\\) success";
static char	*regex_proctitle1 = ".*proctitle=\\([0-9|A-F].*\\) ";
static char	*regex_proctitle2 = ".*proctitle=\\(\".*\"\\)";

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
    int	rc;
    size_t	sz;
    tbsz = bsz;
    tmpbuf = malloc(bsz);
    if (tmpbuf == NULL) {
	fprintf(stderr, "Cannot allocate memory\n");
	exit(-1);
    }
    if ((rc = regcomp(&preg_seqnum, regex_seqnum, 0)) < 0) {
	printf("compile error\n");
	sz = regerror(rc, &preg_seqnum, errbuf, 1024);
	printf("errbuf=%s\n", errbuf);
    }
    if ((rc = regcomp(&preg_syscall, regex_syscall, 0)) < 0) {
	printf("compile error\n");
	sz = regerror(rc, &preg_syscall, errbuf, 1024);
	printf("errbuf=%s\n", errbuf);
    }
    if ((rc = regcomp(&preg_proctitle1, regex_proctitle1, 0)) < 0) {
	printf("compile error\n");
	sz = regerror(rc, &preg_proctitle1, errbuf, 1024);
	printf("errbuf=%s\n", errbuf);
    }
    if ((rc = regcomp(&preg_proctitle2, regex_proctitle2, 0)) < 0) {
	printf("compile error\n");
	sz = regerror(rc, &preg_proctitle2, errbuf, 1024);
	printf("errbuf=%s\n", errbuf);
    }
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
    sz = pmatch[1].rm_so, pmatch[1].rm_eo;
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
    sz = pmatch[1].rm_so, pmatch[1].rm_eo;
    // printf("start=%d, end=%d, sz = %ld\n", pmatch[1].rm_so, pmatch[1].rm_eo, sz);
    
    strncpy(rslt, &msg[pmatch[1].rm_so], sz);
    rslt[sz] = 0;
    // printf("%s(%d,%d)\n", tmpbuf, pmatch[1].rm_so, pmatch[1].rm_eo);
    return sz;
}

int
msg_seqnum(char *msg, long *rslt)
{
    int	rc;
    rc = regex_pattern1(&preg_seqnum, msg, rslt);
    return rc;
}

int
msg_syscall(char *msg, long *rslt)
{
    int	rc;
    rc = regex_pattern1(&preg_syscall, msg, rslt);
    return rc;
}

int
msg_proctitle(char *msg, char *rslt)
{
    int	rc;
#if 0
    rc = regex_pattern2(&preg_proctitle, msg, tmpbuf);
    printf("%s: msg=%s\n\ttmpbuf=%s\n", __func__, msg, tmpbuf);
    rc = hex2ascii(tmpbuf, rslt);
#endif
    rc = regex_pattern2(&preg_proctitle1, msg, rslt);
    if (rc < 0) {
	rc = regex_pattern2(&preg_proctitle2, msg, rslt);
    }
    return rc;
}
