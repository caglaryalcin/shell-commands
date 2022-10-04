## shell-commands

PS commands I use often

#### Remote PS
```powershell
Enter-PSSession -ComputerName nameishere
```

#### Remote cmd
```powershell
psexec \\hostname cmd
```

#### Check .net version
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | Select-Object Version
```

#### Get hyper-v host
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters\' | Select-Object HostName
```

#### Sscm installed apps
```powershell
get-wmiobject -query "SELECT * FROM CCM_Application" -namespace "ROOT\ccm\ClientSDK" | Select-Object FullName, InstallState
```

#### Get sscm apps
```powershell
get-wmiobject -query "SELECT * FROM CCM_Application" -namespace "ROOT\ccm\ClientSDK" | Select-Object FullName, InstallState
```

#### Installed softwares LOOK
```powershell
get-wmiobject -Class Win32_Product | Select-Object Name, Version
```

#### Check hash
```powershell
Get-FileHash .\dosya -Algorithm SHA256
```

#### Install sscm agent
```powershell
CCMSetup.exe /mp:sub.domain.com SMSSITECODE=domainsitecode FSP=sscmserver.domain.com
```

#### Collectively Move all AD OU
```powershell
Get-Content C:\import.txt| foreach {Get-ADComputer -Filter {Name -Like $_} |Move-ADObject -TargetPath "OU=Tier0,OU=App Servers,OU=OU,OU=OU,DC=DC,DC=local"}
```

#### Get permissions
```powershell
net localgroup Administrators
net localgroup "Remote Desktop Users"
```

#### Exchange Mail Inbox Check
```powershell
Get-TransportService | Get-MessageTrackingLog -start "9/22/2022 9:00:00 AM" -end "9/22/2022 3:00:00 PM" -Sender "sender@mail.com" -Recipients "recipients@mail.com"
```

#### Set Mail AutoReply
```powershell
Set-MailboxAutoReplyConfiguration ADUSERNAME -AutoReplyState enabled -ExternalAudience all -InternalMessage "Message was here"
```

#### Get locked user from domain
```powershell
Search-ADAccount -LockedOut -ResultPageSize 2000 -resultSetSize $null | Select-Object Name, SamAccountName, DistinguishedName | Export-CSV “C:\LockedUserList.CSV” -NoTypeInform
```

#### Get user mail export
```powershell
New-MailboxExportRequest -Mailbox username -AcceptLargeDataLoss -BadItemLimit 150 -FilePath \\filepath\file.pst
```

#### Get domain users
```powershell
Get-ADUser -server adserver.domain.com -Filter {enabled -eq "true" -and objectclass -eq "user"} -properties lastlogondate, enabled | Select-Object Name,SamAccountName,lastlogondate, enabled | 
Export-csv C:\domain_users.csv -NoTypeInformation -Encoding UTF8
```

---------------------

```powershell
$attributes = 'EmployeeID','Name','SamAccountName','Description','PasswordLastSet','emailaddress','PasswordNeverExpires','whencreated','whenchanged','lastlogondate',@{n='lastlogontimeStamp';e={[DateTime]::FromFileTime($_.lastlogontimestamp)}},'enabled'
 
Get-ADUser -server adserver.domain.com -Filter {enabled -eq "true" -and objectclass -eq "user"} -properties * | select $attributes | 
Export-csv C:\domain_users.csv -NoTypeInformation -Encoding UTF8 -Delimiter ";" 
```

#### Get mail address from AD users
```powershell
Get-ADObject -Filter {(objectclass -eq 'contact') -and ((targetaddress -like "*domain.com*") -or (targetaddress -like "*filteradresshere*"))} -Properties *  | 
select cn,targetaddress,memberof,objectclass | out-file c:\therearefilter_contacts.csv 
```
