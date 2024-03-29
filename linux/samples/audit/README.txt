%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Tools installation
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# sudo  apt-get install curl lsb-release -y
$ sudo apt-get install emacs screen -y
$ sudo apt-get install net-tools -y
$ sudo apt-get install dns-utils -y
$ sudo apt-get install git -y
$ sudo apt-get install make gcc g++ gdb -y
sudo apt-get install -y autoconf automake libtool autoconf-doc libtool-doc swig
sudo apt-get install -y libcjson-dev xsltproc libssl-dev

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Testing Audit
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
The libaudit-dev package for Ubuntu 20.04 is an old version.
We should use the latest libaudit instead of "sudo apt-get install libaudit-dev"

(1.1) How to install libaudit
$ sudo apt-get update
$ sudo apt-get install -y autoconf automake libtool autoconf-doc libtool-doc swig
$ git clone https://github.com/linux-audit/audit-userspace.git
$ cd audit-userspace
$ ./autogen.sh
$ ./configure --disable-zos-remote --with-aarch64
$ make
$ sudo make install
$ export LD_LIBRARY_PATH=:/usr/local/lib:$LD_LIBRART_PATH
$ export export MANPATH=:/usr/local/man:$MANPATH
$ mkdir -p /var/log/auditd

(1.2) How to install mosquitto
$ sudo apt-get install -y libcjson-dev xsltproc libssl-dev
$ sudo apt-get install -y docbook-xsl
$ sudo git clone https://github.com/eclipse/mosquitto.git
$ make
  # error happens during man page creation.
$ cd lib
$ sudo make install
$ cd lib/cpp
$ sudo make install


(2) How to compile and run the audit-test sample program.
$ cd test
$ make
$ sudo bash
  # export LD_LIBRARY_PATH=:/usr/local/lib
  ######## auditctl -a always,exit -S all
  # ./audit-test -v
 1) To see registered rules,
   # auditctl -l
 2) To delete all rules
   # auditctl -D
 3) The following command is the same rule in the audit-test sample program.
  # auditctl -a always,exit -S all
 4) To disable audit
  # auditctl -e 0
 5) To see all system call names and numbers
  $ ausyscall --dump

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
(3) How to run auditd
  $ sudo bash
  # export LD_LIBRARY_PATH=:/usr/local/lib
  # auditd -f -n -s enable -c /usr/local/etc/audit >& /dev/null
  # auditctl -a always,exit -S all
  # auditctl -D
  # auditctl -l
  # auditd -f -n -s enable >& /dev/null
  # auditctl -a always,exit -F arch=b64 -S execve,clone,exit,exit_group
  
(4) How to analyze a log file
  process ID 43755の解析例
  $ ausearch -p 43755 -if LOG.audit
  $ ausearch -p 43755 -if LOG.audit --interpret
  This tool shows a set of kernel events related to a system call.
  The following URL help you to understand the ausearch.
  https://access.redhat.com/documentation/ja-jp/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files

(5) plugin
   $ /usr/local/etc/audit

(6) docker
   $ sudo docker run -itd --privileged --cap-add=ALL --pid=host --name mytest -v /mnt2:/remote audit_mqtt
   $ docker exec -it mytest
     # auditctl -a always,exit -F arch=b64 -S clone,execve,exit,exit_group
     # auditd -f -n -s enable -c /usr/local/etc/audit >& /dev/null

   $ docker save audit_mqtt -o audit_mqtt.tar
   $ docker load -i audit_mqtt.tar

## for docker installation, see
	https://docs.docker.com/engine/install/ubuntu/

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
- SYSCALL
audit(1632288380.516:296876): arch=c000003e syscall=7 success=yes exit=0 a0=7fd2c8000b60 a1=2 a2=7d0 a3=7fd2cfffe930 items=0 ppid=1 pid=2724 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="GUsbEventThread" exe="/usr/libexec/fwupd/fwupd" subj=unconfined key=(null)

- PATH
audit(1632382442.931:297291): item=0 name="/var/lib/fwupd/remotes.d/lvfs-testing" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Building audit-userspace
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
$ ./autogen.sh
$ ./configure --prefix=/mnt1/ishikawa/ztiot/ --disable-zos-remote

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
SSH
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
$ sudo apt install openssh-server
$ sudo systemctl status ssh

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
URL
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
mqtt://<host name>[:<port>]
mqtts://<host name>[:<port>]
file://<path>
Options
   server=mqtt://ubuntu,logfile=file:///tmp/LOG

https://access.redhat.com/documentation/en/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types

https://access.redhat.com/documentation/ja-jp/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types

https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-audit-comp.html


以下のURLはなんだ？
https://securityonline.info/auditd-attack-mitres-attack-framework/
https://github.com/bfuzzy/auditd-attack/blob/master/auditd-attack.rules

https://attack.mitre.org/matrices/enterprise/linux/

https://attack.mitre.org/techniques/T1078/

https://listman.redhat.com/archives/linux-audit/

--------------------------------------------------------
About auditd program
in auditd.c
      ev_io_init (&netlink_watcher, netlink_handler, fd, EV_READ);
      ev_io_start (loop, &netlink_watcher);

static void
netlink_handler(struct ev_loop *loop, struct ev_io *io, int revents)
   call distribute_event()

void distribute_event(struct auditd_event *e)
	/* Next, send to plugins */
	if (route)
		dispatch_event(&e->reply, proto);

in auditd-dispatch.c
int dispatch_event(const struct audit_reply *rep, int protocol_ver)
  return  libdisp_enqueue(e);

in audisp/audispd.c
int libdisp_enqueue(event_t *e)
            calling enqueue(e, &daemon_config);

---------------------------------------------------
Here is a plugin module audisp
In audisp/audispd.c,

int start_one_plugin(lnode *conf)
    safe_exec(...)

int safe_exec(plugin_conf_t *conf)
       socketpair()
       fork & exec
----------------------
in audisp/audispd.c
void *outbound_thread_main(void *arg) is defined
   in which the audit messages are sent to all the plugin processes.

int event_loop(void) is also defined.
   in which an event is extracted via an queue operation defined in queue.c

static int event_loop(void)
   call  send_af_unix_string(const char *s, unsigned int len)

NOT
audisp/audispd-builtins.c
void send_af_unix_string(const char *s, unsigned int len)
 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
auparse.c
static void consume_feed(auparse_state_t *au, int flush)
       	while (auparse_next_event(au) > 0) {
		if (au->callback) {
			(*au->callback)(au, AUPARSE_CB_EVENT_READY,
					au->callback_user_data);
		}
	}

int auparse_next_event(auparse_state_t *au)
{
	clear_normalizer(&au->norm_data);
	return au_auparse_next_event(au);
}

static int au_auparse_next_event(auparse_state_t *au)
{
	if ((l = au_get_ready_event(au, 0)) != NULL) {
	   Here we see ready list, but not extracted
	}
}

int auparse_feed_has_ready_event(auparse_state_t *au)
{
	if (au_get_ready_event(au, 1) != NULL)
		return 1;

	return 0;
}
