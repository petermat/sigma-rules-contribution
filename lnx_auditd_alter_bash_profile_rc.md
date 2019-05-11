# SIGMA Rule - alter .bash_profile and .bashrc [T1156]

Bash profile configuration files could be abused by attacker to grand persistense, record passwords from console or launch reverse shell. This rule monitor changes in relates files.


## MITRE Attack  classification

ID: [T1156](https://attack.mitre.org/techniques/T1156/)
Tactic: Persistence
Platform:  Linux, macOS
Permissions Required:  User, Administrator
Data Sources: File monitoring,


## Audit Deamon config & log Sample

AuditD Shell configuration Persistence Related Events:

	-w /home/<user>/.bashrc -k T1156_bash_profile_and_bashrc
	-w /home/<user>/.bash_profile -k T1156_bash_profile_and_bashrc
	-w /home/<user>/.profile -k T1156_bash_profile_and_bashrc
	-w /etc/profile.d/ -k T1156_bash_profile_and_bashrc
	-w /etc/profile -k T1156_bash_profile_and_bashrc
	-w /etc/shells -k T1156_bash_profile_and_bashrc
	-w /etc/bashrc -k T1156_bash_profile_and_bashrc
	-w /etc/csh.cshrc -k T1156_bash_profile_and_bashrc
	-w /etc/csh.login -k T1156_bash_profile_and_bashrc

AuditD Log samples:

	```
	type=SYSCALL msg=audit(1557611367.253:105492): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=556847dbbd70 a2=441 a3=1b6 items=2 ppid=7441 pid=7442 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=35 comm="bash" exe="/bin/bash" key="T1156_bash_profile_and_bashrc"
	type=CWD msg=audit(1557611367.253:105492): cwd="/home/peter"
	type=PATH msg=audit(1557611367.253:105492): item=0 name="/home/peter/" inode=661921 dev=08:02 mode=040755 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
	type=PATH msg=audit(1557611367.253:105492): item=1 name="/home/peter/.bashrc" inode=661923 dev=08:02 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
	type=PROCTITLE msg=audit(1557611367.253:105492): proctitle="-bash"
	```


	```
	type=USER_CMD msg=audit(1557611856.809:105507): pid=7774 uid=1000 auid=1000 ses=35 msg='cwd="/home/peter" cmd=6E616E6F202F6574632F7368656C6C73 terminal=pts/1 res=success'
	type=CRED_REFR msg=audit(1557611856.809:105508): pid=7774 uid=0 auid=1000 ses=35 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
	type=USER_START msg=audit(1557611856.813:105509): pid=7774 uid=0 auid=1000 ses=35 msg='op=PAM:session_open acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
	type=SYSCALL msg=audit(1557611856.841:105510): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55e641878600 a2=0 a3=0 items=1 ppid=7774 pid=7775 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=35 comm="nano" exe="/bin/nano" key="T1156_bash_profile_and_bashrc"
	type=CWD msg=audit(1557611856.841:105510): cwd="/home/peter"
	type=PATH msg=audit(1557611856.841:105510): item=0 name="/etc/shells" inode=787187 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
	type=PROCTITLE msg=audit(1557611856.841:105510): proctitle=6E616E6F002F6574632F7368656C6C73
	type=SYSCALL msg=audit(1557611856.849:105511): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55e6418db3a0 a2=441 a3=1b6 items=2 ppid=7774 pid=7775 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=35 comm="nano" exe="/bin/nano" key="T1156_bash_profile_and_bashrc"
	type=CWD msg=audit(1557611856.849:105511): cwd="/home/peter"
	type=PATH msg=audit(1557611856.849:105511): item=0 name="/etc/" inode=786433 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
	type=PATH msg=audit(1557611856.849:105511): item=1 name="/etc/shells" inode=787187 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
	type=PROCTITLE msg=audit(1557611856.849:105511): proctitle=6E616E6F002F6574632F7368656C6C73
	```


## License

This project is licensed under the MIT License.

## Acknowledgments

Inspiration, code snippets, etc.
* [Linux.Mirai.1548](https://vms.drweb.fr/virus/?i=17307776)
* [Linux Rabbit/Rabbot Malware](https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat)
* [sudo password sniffing](http://turbochaos.blogspot.com/2013/11/ghetto-privilege-escalation-with-bashrc.html)
* [Sudo-Backdoor : Wrapper to sudo for stealing user Password](http://seclist.us/sudo-backdoor-wrapper-to-sudo-for-stealing-user-password.html)
* [Persistence Using ~/bashrc and Web Delivered Malware](https://books.google.nl/books?id=dBKLDwAAQBAJ&lpg=PA555&ots=dWRutOYrvn&dq=malware%20%20bashrc&pg=PA556#v=onepage&q=malware%20%20bashrc&f=false)


