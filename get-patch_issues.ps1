import-module activedirectory
#Get BaseDN
$base_dn = (get-addomain).DistinguishedName
#Get DCs
$domaincontrollers = (get-addomain).replicadirectoryservers
#Get servers
$servers = get-adcomputer -SearchBase $base_dn -filter 'OperatingSystem -like "*Server*"'
$results = @()

#AD Permissions changes (https://support.microsoft.com/en-us/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1)
$ad_eventIDs = 3044,3045,3046,3047,3048,3049,3050,3051,3052,3053,3054,3055
foreach ($domaincontroller in $domaincontrollers) {
    $results += Invoke-Command -ComputerName $domaincontroller -ScriptBlock{ Get-WinEvent -FilterHashtable @{Logname = "System" ; ID = $args[0]} -ea silentlycontinue } -ArgumentList $ad_eventIDs
}

#DCOM changes (https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
foreach ($server in $servers){
    $results += Invoke-Command -ComputerName $server.dnshostname -ScriptBlock{ Get-WinEvent -FilterHashtable @{Logname = "System" ; ID = 10036} -ea silentlycontinue }
}

#Netlogon changes (https://support.microsoft.com/en-us/topic/kb5021130-how-to-manage-the-netlogon-protocol-changes-related-to-cve-2022-38023-46ea3067-3989-4d40-963c-680fd9e8ee25)
$netlogon_eventIDs = 5838,5839,5840,5841
foreach ($domaincontroller in $domaincontrollers){
    $results += Invoke-Command -ComputerName $domaincontroller -ScriptBlock{ Get-WinEvent -FilterHashtable @{Logname = "System" ; ID = $args[0]} -ea silentlycontinue } -ArgumentList $netlogon_eventIDs
}

#Kerberos changes (https://support.microsoft.com/en-us/topic/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967-997e9acc-67c5-48e1-8d0d-190269bf4efb)
$kerb_eventIDs = 43,44
foreach ($domaincontroller in $domaincontrollers){
    $results += Invoke-Command -ComputerName $domaincontroller -ScriptBlock{ Get-WinEvent -FilterHashtable @{ProviderName = "Microsoft-Windows-KdsSvc" ; ID = $args[0]} -ea silentlycontinue } -ArgumentList $kerb_eventIDs
}

$results
$results | export-csv -NoTypeInformation -Encoding UTF8 patch_issues.csv