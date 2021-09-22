Testing Audit
The libaudit-dev package for Ubuntu 20.04 is an old version.
We should use the latest libaudit.
	$ sudo apt-get install libaudit-dev

(1) How to install libaudit
$ sudo apt-get install autoconf automake libtool autoconf-doc libtool-doc
$ git clone https://github.com/linux-audit/audit-userspace.git
$ cd audit-userspace
$ autogen.sh
$ ./configure --disable-zos-remote
$ make
$ sudo make install
$ export LD_LIBRARY_PATH=:/usr/local/lib:$LD_LIBRART_PATH
$ export export MANPATH=:/usr/local/man:$MANPATH

(2) How to compile and run the audit-test sample program.
$ cd test
$ make
$ sudo bash
  # export LD_LIBRARY_PATH=:/usr/local/lib
  # auditctl -a always,exit -S all
  # ./audit-test
 1) To see registered rules,
   # auditctl -l
 2) To delete all rules
   # auditctl -D
 3) The following command is the same rule in the audit-test sample program.
  # auditctl -a always,exit -S all

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
(3) How to run auditd
  $ sudo bash
  # export LD_LIBRARY_PATH=:/usr/local/lib
  # auditd -f -n -s enable
  # auditctl -a always,exit -S all
  
(3) How to analyze a log file
  process ID 43755§Œ≤Ú¿œŒ„
  $ ausearch -p 43755 -if LOG.audit
  $ ausearch -p 43755 -if LOG.audit --interpret
  This tool shows a set of kernel events related to a system call.
  The following URL help you to understand the ausearch.
  https://access.redhat.com/documentation/ja-jp/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files
