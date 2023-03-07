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

#### Delete files with cmd
```powershell
rmdir /s /q C:\Windows.old
```
```powershell
takeown /F "C:\Windows.old" /A /R /D Y
```
```powershell
RD /S /Q "C:\Windows.old"
```

#### .net 3.5 setup (Source:Windows iso)
```powershell
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:X:\sources\sxs
```

#### Check .net version
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | Select-Object Version
```

#### Get hyper-v host
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters\' | Select-Object HostName
```

#### Check hash
```powershell
Get-FileHash .\dosya -Algorithm SHA256
```

#### Get permissions
```powershell
net localgroup Administrators
net localgroup "Remote Desktop Users"
```

#### Get users with ID (local)
```powershell
gwmi win32_userprofile | select localpath, sid
```

#### Get user from group
```powershell
Get-ADGroupMember -Identity "groupname" -Recursive | Get-ADUser -Properties Name,  EmployeeID, userPrincipalName, distinguishedName
```

#### Get user from group with export
```powershell
Get-ADGroupMember -Identity "groupname" -Recursive | Get-ADUser -Properties Name, EmployeeID, userPrincipalName, distinguishedName | Export-csv -path C:\caglar-export\test.csv -notypeinformation -Encoding UTF8 
```

#### List dc
```powershell
Get-ADDomainController -Filter * | Select hostname, site
```

#### Install Telnet Client
```powershell
Install-WindowsFeature -name Telnet-Client
```

#### Get locked user from domain
```powershell
Search-ADAccount -LockedOut -ResultPageSize 2000 -resultSetSize $null | Select-Object Name, SamAccountName, DistinguishedName | Export-CSV “C:\LockedUserList.CSV” -NoTypeInform
```

#### Get Group Member from AD
```powershell
Get-ADGroupMember -Identity 'Groupname' -Recursive | Select Name
```

#### Get Active Users on AD
```powershell
Get-ADUser -server dc.hostname.com -Filter {enabled -eq "true" -and objectclass -eq "user"} -properties * | Select-Object Name,SamAccountName,lastlogondate | 
Export-csv C:\DomainUsers.csv -NoTypeInformation -Encoding UTF8
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

#### Get name and mail address from AD groups
```powershell
Get-ADGroup -properties * -Filter  {(name -like "*sube grubu*")} |select name,mail | Export-Csv "C:\SubeGrubu.csv" -Encoding UTF8 -NoTypeInformation
```

#### Get last modified date of computer object from AD
```powershell
Get-ADcomputer -Filter 'Name -like "*computernamewashere"' -properties * | sort lastlogondate | FT name, whenChanged
```

#### Get OU of hostname from AD
```powershell
Get-ADcomputer -Filter 'Name -like "*computernamewashere"' -properties * | sort lastlogondate | FT name, CanonicalName
```

#### Get OU of hostname list from AD
```powershell
Get-Content C:\hostnames.txt | foreach {Get-ADComputer -Filter {Name -Like $_} -properties *} | sort lastlogondate | FT name, CanonicalName
```

#### Change dns of servers
```powershell
$servers = Get-Content "E:\liste.txt"
#$servers = "hostname"
foreach($server in $servers){
    Write-Host "Connect to $server..."
    $nics = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $server   | Where{$_.IPEnabled -eq "TRUE"}
    $newDNS = "1.1.1.1","1.0.0.1"
foreach($nic in $nics){
    Write-Host "`tExisting DNS Servers " $nic.DNSServerSearchOrder
    $x = $nic.SetDNSServerSearchOrder($newDNS)
    if($x.ReturnValue -eq 0){
    Write-Host "`tSuccessfully Changed DNS Servers on " $server -ForegroundColor Green
     }
     else{
     Write-Host "`tFailed to Change DNS Servers on " $server -ForegroundColor Red
         }
   }
}
```

#### Check disk size
```powershell
Get-Volume -DriveLetter C
```

#### Set TR Timezone
```powershell
Set-TimeZone -Id "Turkey Standard Time"
```

#### Applications sent from SCCM
```powershell
get-wmiobject -query "SELECT * FROM CCM_Application" -namespace "ROOT\ccm\ClientSDK" | Select-Object FullName, InstallState
```

#### Get installed softwares
```powershell
get-wmiobject -Class Win32_Product | Select-Object Name, Version
```

#### Get services status
```powershell
Get-Service -Name "servicesname*"
```
```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```
```powershell
Get-Service "s*" | Sort-Object status
```

#### To get information about the last time the servers communicated with the domain
```powershell
$ComputerList = get-content "E:\Liste.txt"
#$ComputerList = "hostname"
  foreach ($Computer in $ComputerList)
{
  TRY
    {
  $LastLogonQuery = Get-ADComputer $Computer -Properties lastlogontimestamp | 
    #Select-Object @{n="Computer";e={$_.Name}}, @{Name="Lastlogon"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}}
    Select-Object @{n='lastLogonTimestamp';e={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString("dd/MM/yyyy")}}
     $Computer   +  "*ADLastLogonTime*"  + $LastLogonQuery.lastLogonTimestamp
 }
Catch    {
   $Computer   +  "*ADLastLogonTime*"  + "NOObject"
	}
}
```

#### Install sscm agent
```powershell
CCMSetup.exe /mp:sub.domain.com SMSSITECODE=domainsitecode FSP=sscmserver.domain.com
```

#### Collectively Move all on AD OU
```powershell
Get-Content C:\import.txt| foreach {Get-ADComputer -Filter {Name -Like $_} |Move-ADObject -TargetPath "OU=Tier0,OU=App Servers,OU=OU,OU=OU,DC=DC,DC=local"}
```

#### Get samaccountname from name and surname
```powershell
Get-ADUser -Filter 'Name -like "*namesurname"' | Format-Table Name,SamAccountName -A
```

#### Get userPrincipalNames from samaccountname
```powershell
Get-ADUser accountname -Properties * | select userPrincipalName
```

#### Exchange Mail Inbox Receipt Check
```powershell
Get-TransportService | Get-MessageTrackingLog -start "9/22/2022 9:00:00 AM" -end "9/22/2022 3:00:00 PM" -Sender "sender@mail.com" -Recipients "recipients@mail.com"
```

#### Set Mail AutoReply
```powershell
Set-MailboxAutoReplyConfiguration ADUSERNAME -AutoReplyState enabled -ExternalAudience all -InternalMessage "Message was here"
```

#### Get user mail export
```powershell
(all)
New-MailboxExportRequest -Mailbox username -AcceptLargeDataLoss -BadItemLimit 150 -FilePath \\filepath\file.pst
(The date is intermittent / The dates should be set according to the zone setting of the machine to be exported)
New-MailboxExportRequest -ContentFilter {(Received -lt '07/26/2021') -and (Received -gt '07/05/2021')} -Mailbox "ADusername" -Name nameishere -FilePath \\filepath\inboxname.pst
(status export)
Get-MailboxExportRequest
(remove of completed)
Get-MailboxExportRequest -Status completed | Remove-MailboxExportRequest
```

#### Get mail groups from AD (run with exc management shell)
```powershell
Get-DistributionGroup -Filter * -ResultSize unlimited |select name, PrimarySmtpAddress  | Export-Csv c:\MailGroup.csv -NoTypeInformation -Encoding UTF8
```

#### Get 0kb files from path
```powershell
Get-ChildItem -Path C:\SourcePATH -Recurse -Force | Where-Object { $_.PSIsContainer -eq $false -and $_.Length -eq 0 } | Select -ExpandProperty FullName | Add-Content -Path c:\export.txt
```
