# Directory Bruteforce

## Interesting Wordlists

```bash
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/dirb/wordlists/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

### Extensions
**Apache:** .php, .asp, .txt, .xml, .bak  
**IIS:** .asp, .aspx, ashx, wsdl, wadl, asmx, .xml, .zip, .txt, .ini, .tmp, .bak, .old, .html, .htm

## Gobuster

```bash
gobuster dir -u http://<TARGET-IP> -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -t 30 -x .php,.txt

-t              = threads
-x              = extensions
-f              = adds a "/" at the end
-o              = output to a file
--hide-length   = hide response with lentgth X
```

## Dirsearch

```bash
dirsearch -u http://10.10.110.100:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -r -e php,txt,asp -f

-f =	will force extensions and apend a "/" at the end of each try. (must use for seclists!!)
-e =	extensions
-r =	recursive
```

## Ffuf

```bash
ffuf -c -t 100 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://10.10.10.150:8080/FUZZ -e .html,.php

-recursion -recursion-depth 1 = Recursive / How many levels to spider
-fc =	Filter HTTP status codes from response. Comma separated list of codes and ranges
-fl =	Filter by amount of lines in response. Comma separated list of line counts and ranges
-fr =	Filter regexp
-fs =	Filter HTTP response size. Comma separated list of sizes and ranges
-fw =	Filter by amount of words in response. Comma separated list of word counts and ranges
```

## Feroxbuster

Recursively brute-force directories.

```python
feroxbuster -u http://machine.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```