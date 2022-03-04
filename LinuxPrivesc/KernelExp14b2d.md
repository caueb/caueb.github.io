# Kernel Exploit

## Find the Kernel version

```bash
uname -a
```

## Search for exploits

```bash
searchsploit linux kernel 2.6 debian
```

## Tool - Linux Exploit Suggester

```bash
linux-exploit-suggester-2.pl -k 2.6.32
```

## OS System running

```bash
cat /etc/os-release
```

## Kernel Version

```bash
uname -a
```

## GCC Compile 32Bit Exploit on 64Bit Kali

```bash
gcc -m32 exploit.c -o exploit
```