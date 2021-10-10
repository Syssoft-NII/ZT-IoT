The test6 test program does not work on Linux kernel 5.8, Ubuntu20.04
It works on Linux kernel 5.10.60.

(1) How to install libseccomp
$ apt-get install gperf
$ git clone https://github.com/seccomp/libseccomp
$ cd libseccomp
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
SCMP_ACT_LOG
 - audit information is stored into /var/log/syslog
 E.g.,
 Oct  1 12:51:23 ubuntu kernel: [557245.373222] audit: type=1326 audit(1633060283.576:62): auid=1000 uid=1000 gid=1000 ses=297 subj==unconfined pid=730735 comm="test-actlog" exe="/mnt2/ishikawa/work/git/ZT-IoT/linux/samples/seccomp/test-actlog" sig=0 arch=c000003e syscall=5 compat=0 ip=0x7fbd3b5a1689 code=0x7ffc0000
Oct  1 12:51:23 ubuntu kernel: [557245.374451] audit: type=1326 audit(1633060283.576:63): auid=1000 uid=1000 gid=1000 ses=297 subj==unconfined pid=730735 comm="test-actlog" exe="/mnt2/ishikawa/work/git/ZT-IoT/linux/samples/seccomp/test-actlog" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7fbd3b5a21e7 code=0x7ffc0000
Oct  1 12:51:23 ubuntu kernel: [557245.374508] audit: type=1326 audit(1633060283.576:64): auid=1000 uid=1000 gid=1000 ses=297 subj==unconfined pid=730735 comm="test-actlog" exe="/mnt2/ishikawa/work/git/ZT-IoT/linux/samples/seccomp/test-actlog" sig=0 arch=c000003e syscall=32 compat=0 ip=0x7fbd3b5a2a0b code=0x7ffc0000
Oct  1 12:51:23 ubuntu kernel: [557245.374534] audit: type=1326 audit(1633060283.576:65): auid=1000 uid=1000 gid=1000 ses=297 subj==unconfined pid=730735 comm="test-actlog" exe="/mnt2/ishikawa/work/git/ZT-IoT/linux/samples/seccomp/test-actlog" sig=0 arch=c000003e syscall=72 compat=0 ip=0x7fbd3b5a75a4 code=0x7ffc0000
