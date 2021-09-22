#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include "regexplib.h"

#define MAX_AUDIT_MESSAGE_LENGTH 8970

char	buf[MAX_AUDIT_MESSAGE_LENGTH];

char	*msg_scall = "audit(1632288380.516:296876): arch=c000003e syscall=7 success=yes exit=0 a0=7fd2c8000b60 a1=2 a2=7d0 a3=7fd2cfffe930 items=0 ppid=1 pid=2724 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"GUsbEventThread\" exe=\"/usr/libexec/fwupd/fwupd\" subj=unconfined key=(null)";

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

#if 0
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
#endif

int
main(int argc, char **argv)
{
    int		rc;
    long	rslt;

    printf("TEST\n");
    {
	char *title = "2F7573722F7362696E2F4E6574776F726B4D616E61676572002D2D6E6F2D6461656D6F6E";
	int	idx = 0;
	size_t	sz;
	printf("title=%s\n", title);
	while (*(title+idx) != 0) {
	    char	ch = _h2a(title+idx);
	    if (ch == 0) break;
	    printf("%c", ch);
	    idx += 2;
	}
	printf("\n");
	sz = hex2ascii(title, buf);
	printf("hex2ascii = %s (%ld)\n", buf, sz);
    }
    
    regex_init(MAX_AUDIT_MESSAGE_LENGTH);
    rc = msg_seqnum(msg_scall, &rslt);
    if (rc == 0) {
	printf("seqnum = %ld\n", rslt);
    } else {
	printf("seqnum: no match\n");
    }
    rc = msg_syscall(msg_scall, &rslt);
    if (rc == 0) {
	printf("syscall = %ld\n", rslt);
    } else {
	printf("syscall: no match\n");
    }
    return 0;
}

#if 0
char	errbuf[1024];
/*
 * audit(1632288380.516:296876): arch=c000003e syscall=7 success=yes exit=0 a0=7fd2c8000b60 a1=2 a2=7d0 a3=7fd2cfffe930 items=0 ppid=1 pid=2724 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="GUsbEventThread" exe="/usr/libexec/fwupd/fwupd" subj=unconfined key=(null)
 */
char	*tpattern[] = {
    
    "audit(1632288380.516:296876): arch=c000003e syscall=7 success=yes exit=0 a0=7fd2c8000b60 a1=2 a2=7d0 a3=7fd2cfffe930 items=0 ppid=1 pid=2724 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"GUsbEventThread\" exe=\"/usr/libexec/fwupd/fwupd\" subj=unconfined key=(null)",
    "asdasasdasd",
    "asdasasdasd"
};
char	*regex = "audit([0-9].*:\\([0-9].*\\)):";

int
main(int argc, char **argv)
{
    int		cc, i, j;
    regex_t	preg;
    size_t	sz;
    regmatch_t	pmatch[4];
    
    if ((cc = regcomp(&preg, regex, 0)) < 0) {
	printf("compile error\n");
	sz = regerror(cc, &preg, errbuf, 1024);
	printf("errbuf=%s\n", errbuf);
    }

    for (j = 0; j < 3; j++) {
	memset(pmatch, 0, sizeof(pmatch));
	if ((cc = regexec(&preg, tpattern[j], 4, pmatch, 0)) < 0) {
	    printf("error \n");
	    sz = regerror(cc, &preg, errbuf, 1024);
	    printf("errbuf=%s\n", errbuf);
	} else {
	    char buf[128];
	    if (cc == REG_NOMATCH) {
		printf("no match: %s\n", tpattern[j]);
		continue;
	    }
	    printf("match: %s\n", tpattern[j]);
	    for (i = 0; i < 2; i++) {
		memset(buf, 0, 128);
		strncpy(buf, &tpattern[j][pmatch[i].rm_so],
			pmatch[i].rm_eo - pmatch[i].rm_so);
		printf("\t[%d] %s(%d,%d)\n", i, buf, pmatch[i].rm_so, pmatch[i].rm_eo);
	    }
	    strncpy(buf, &tpattern[j][pmatch[1].rm_so],
			pmatch[1].rm_eo - pmatch[1].rm_so);
	    printf("buf(%s)\n", buf);
	}
    }
    regfree(&preg);
    return 0;
}
#endif
