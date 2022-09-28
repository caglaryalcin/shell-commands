# shell-commands



##remote PS
Enter-PSSession -ComputerName nameishere

#remote cmd
psexec \\hostname cmd

#.net version
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | Select-Object Version

#hyper-v host
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters\' | Select-Object HostName

#installed apps
get-wmiobject -query "SELECT * FROM CCM_Application" -namespace "ROOT\ccm\ClientSDK" | Select-Object FullName, InstallState

#sscm apps
get-wmiobject -query "SELECT * FROM CCM_Application" -namespace "ROOT\ccm\ClientSDK" | Select-Object FullName, InstallState

#installed softwares
get-wmiobject -Class Win32_Product | Select-Object Name, Version

##HASH
Get-FileHash .\dosya -Algorithm SHA256

#ITServices
C:\Windows\CCMSetup.exe /mp:WIPRDSCCMmp01.itservices.local SMSSITECODE=INT FSP=WIPRDSCCMmp01.itservices.local

#toplu ou taşıma
Get-Content C:\tmp\Srv1.txt| foreach {Get-ADComputer -Filter {Name -Like $_} |Move-ADObject -TargetPath "OU=Tier0,OU=App Servers,OU=Production Servers,OU=TPP Servers,DC=Tpp,DC=local"}

#reg query
reg query HKLM\System\CurrentControlSet\services\CSAgent\Sim\ /f AG

##permission
net localgroup Administrators
net localgroup "Remote Desktop Users"

#Inbox Check
Get-TransportService | Get-MessageTrackingLog -start "9/22/2022 9:00:00 AM" -end "9/22/2022 3:00:00 PM" -Sender "sturan@osmanlimenkul.com.tr" -Recipients "portfoysaklama@denizbank.com" | Where-Object {$_.EventId -like "FA*"}

| Where-Object {$_.EventId -like "FA*"} |FL >> Verbose mode

#AutoReply
Set-MailboxAutoReplyConfiguration SAVASCID -AutoReplyState enabled -ExternalAudience all -InternalMessage "message"

#get domain users
Get-ADUser -server s0134adrep01.deniz.denizbank.com -Filter {enabled -eq "true" -and objectclass -eq "user"} -properties lastlogondate, enabled | Select-Object Name,SamAccountName,lastlogondate, enabled | 
Export-csv C:\tmp\Deniz_domain_users.csv -NoTypeInformation -Encoding UTF8

---------------------

$attributes = 'EmployeeID','Name','SamAccountName','Description','PasswordLastSet','emailaddress','PasswordNeverExpires','whencreated','whenchanged','lastlogondate',@{n='lastlogontimeStamp';e={[DateTime]::FromFileTime($_.lastlogontimestamp)}},'enabled'
 
Get-ADUser -server s0134adrep01.deniz.denizbank.com -Filter {enabled -eq "true" -and objectclass -eq "user"} -properties * | select $attributes | 
Export-csv C:\tmp\Deniz_users.csv -NoTypeInformation -Encoding UTF8 -Delimiter ";" 

#get mail address
Get-ADObject -Filter {(objectclass -eq 'contact') -and ((targetaddress -like "*denizbank.com*") -or (targetaddress -like "*sberbank*"))} -Properties *  | 
select cn,targetaddress,memberof,objectclass | out-file c:\temp\sber_contacts.csv 



