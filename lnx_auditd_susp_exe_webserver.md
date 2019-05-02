# SIGMA Rule - lnx_auditd_susp_exe_webserver [T1100]

Purpose of this rule is to detect post exploitation techniques by monitoring of shell commands on behalf of Web Server like Apache and Nginx. Web Server is usually running as user UID=33 without assigned tty.


## MITRE Attack  classification

ID: [T1100](https://attack.mitre.org/techniques/T1100/)
Tactic: Persistence, Privilege Escalation
Platform:  Linux, macOS
System Requirements:  Adversary access to Web server with vulnerability or account to upload and serve the Web shell file.
Effective Permissions:  SYSTEM, User
Data Sources:  Process monitoring

## Minimal Audit Deamon configuration

Configuration to record execution of 32 & 64 bit executables of user `uid=33` :
```
auditctl -a exit,always -F arch=b64 -F uid=33 -S execve -k auditcmd
auditctl -a exit,always -F arch=b32 -F uid=33 -S execve -k auditcmd
```


## Audit Deamon log Sample

```
type=SYSCALL msg=audit(1556784879.934:140): arch=c000003e syscall=59 success=yes exit=0 a0=7f70bd6b3e9a a1=7ffeecd0c550 a2=7ffeecd0f348 a3=1 items=2 ppid=1224 pid=1928 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="sh" exe="/bin/dash" key="auditcmd"
type=EXECVE msg=audit(1556784879.934:140): argc=3 a0="sh" a1="-c" a2=77686F616D6920323E2631
type=CWD msg=audit(1556784879.934:140): cwd="/var/www/html"
type=PATH msg=audit(1556784879.934:140): item=0 name="/bin/sh" inode=131124 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=PATH msg=audit(1556784879.934:140): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=918266 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=PROCTITLE msg=audit(1556784879.934:140): proctitle=7368002D630077686F616D6920323E2631
type=SYSCALL msg=audit(1556784879.938:141): arch=c000003e syscall=59 success=yes exit=0 a0=5579238a0bb0 a1=5579238a0b40 a2=5579238a0b50 a3=7f00e9105810 items=2 ppid=1928 pid=1929 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="whoami" exe="/usr/bin/whoami" key="auditcmd"
type=EXECVE msg=audit(1556784879.938:141): argc=1 a0="whoami"
type=CWD msg=audit(1556784879.938:141): cwd="/var/www/html"
type=PATH msg=audit(1556784879.938:141): item=0 name="/usr/bin/whoami" inode=937 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=PATH msg=audit(1556784879.938:141): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=918266 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=PROCTITLE msg=audit(1556784879.938:141): proctitle="whoami"
```

## SIGMA Code

```
title: Detects Executions on Behalf of Web Server
status: experimental
description: Purpose of this rule is to detect post exploitation techniques by monitoring of shell commands on behalf of Web Server like Apache and Nginx. Web Server is usually running as user UID=33 without assigned tty.
references:
    - 'Internal Research - mostly derived from observing web shell artefacts'
date: 2019/05/02
author: Peter Matkovski
logsource:
    product: linux
    service: auditd
detection:
    cmd:
        - type: 'SYSCALL'
          success: 'yes'
          uid: '33'
          tty: '(none)'
          comm: 'sh'
          exe: '/bin/dash'
    condition: cmd
falsepositives:
    - Crazy Web Applications 
level: medium
```

## Version History

* 0.2
    * Various bug fixes and optimizations
* 0.1
    * Initial Release

## License

This project is licensed under the MIT License.

## Acknowledgments

Inspiration, code snippets, etc.
* [Detection of PHP Web Shells with Access log, WAF and Audit Deamon](https://medium.com/@p.matkovski/detection-of-php-web-shells-with-access-log-waf-and-audit-deamon-e798d4c95ec)
* [Detection of PHP Web Shells with SIGMA](https://medium.com/@p.matkovski/detection-of-php-web-shells-with-sigma-475de8386d2b)