/*
 *	This is an adhoc test program to understand seccomp.
 *						2021/10/01
 *				yutaka_ishikawa@nii.ac.jp
 *	Using prctl and seccomp syscalls and capturing getpid() syscall.
 *	Usage:
 *	./test			causing core dump
 *	./test any_string	shows the negative value of getpid
 */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

#ifndef seccomp
int seccomp(unsigned int op, unsigned int flags, void *args)
{
    errno = 0;
    return syscall(__NR_seccomp, op, flags, args);
}
#endif

struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

struct sock_fprog prog = {
    .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
};


int main(int argc, char **argv)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }
    //if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)){
    printf("No argument of this program issues the seccomp() syscall "
	   "that results in core dump.\n"
	   "More than one argument (any string) shows the negative "
	   "value of actual pid\n");
    if (argc == 1) {
	printf("** Issue seccomp\n");
	if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)){
	    perror("seccomp");
	}
    } else {
	printf("** No seccomp\n");
    }
    pid_t pid = getpid();
    printf("pid = %d\n", pid);

    return 0;
}
