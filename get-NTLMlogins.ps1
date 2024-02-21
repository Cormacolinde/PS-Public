$date = get-date -UFormat %Y%m%d
Try{
    $logins = Get-WinEvent -FilterHashtable @{
                    LogName='Security'
                    ID=4624
                    }
}
Catch{
    write-warning "Unable to get log."
    continue
}
#Clear-EventLog -LogName Security -ComputerName $server -ea SilentlyContinue
    
$results = @()

foreach ($login in $logins) {
    [xml]$xml = $login[0].toxml()
    if (($xml.Event.EventData.Data | where-object {$_.Name -eq 'AuthenticationPackageName'})."#text" -eq "NTLM"){
        $result = New-Object -type psobject
        $result |Add-Member -MemberType NoteProperty -Name TargetUserName -Value $(($xml.Event.EventData.Data | where-object {$_.Name -eq 'TargetUserName'})."#text")
        $result |Add-Member -MemberType NoteProperty -Name WorkstationName -Value $(($xml.Event.EventData.Data | where-object {$_.Name -eq 'WorkstationName'})."#text")
        $result |Add-Member -MemberType NoteProperty -Name IpAddress -Value $(($xml.Event.EventData.Data | where-object {$_.Name -eq 'IpAddress'})."#text")
        $result |Add-Member -MemberType NoteProperty -Name LmPackageName -Value $(($xml.Event.EventData.Data | where-object {$_.Name -eq 'LmPackageName'})."#text")
        $results += $result
    }
}
$results | Sort-Object -property TargetUserName -unique -Descending | export-csv -Encoding UTF8 "C:\scripts\$server`_$date.csv"
