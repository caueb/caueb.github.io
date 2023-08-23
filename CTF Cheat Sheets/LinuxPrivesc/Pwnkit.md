# Pwnkit
Polkit (formerly PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems. It provides an organized way for non-privileged processes to communicate with privileged processes. It is also possible to use polkit to execute commands with elevated privileges using the command pkexec followed by the command intended to be executed (with root permission).

## Linux distributions
| Distribution | Vulnerable? |
| - |- | 
| RHEL 7 | No |
| RHEL 8 | Yes |
| Fedora 20 (or earlier) | No |
| Fedora 21 (or later) | Yes |
| Debian 10 (“buster”) | No |
| Debian testing (“bullseye”) |	Yes |
| Ubuntu 18.04 | No |
| Ubuntu 20.04 | Yes |

## Exploit
### Compiling
- https://github.com/ly4k/PwnKit  
- https://github.com/arthepsy/CVE-2021-4034

### In Python
- https://github.com/ravindubw/CVE-2021-4034
- https://github.com/joeammond/CVE-2021-4034

### Bash
- https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation