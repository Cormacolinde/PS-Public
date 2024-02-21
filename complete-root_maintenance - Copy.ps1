#This script completes the Root CRL maintenance. Log onto the Root server and run start-root_maintenance.ps1 first
Param (
    [parameter(HelpMessage="Base folder where files are kept")]
    [string]$ca_folder="C:\CA",
    [parameter(HelpMessage="Use this switch to enable CRL AD publishing")]
    [switch]$no_maintenancetask,
    [parameter(HelpMessage="Base folder where files are kept")]
    [string]$maintenance_task="CA Maintenance",
    [parameter(HelpMessage="Use this switch to enable CRL AD publishing")]
    [switch]$dspublish
)

#Set variable
$root_folder = $ca_folder
#Copy CRL to the CertEnroll folder
Try{
    copy-item -path "$root_folder\Root\*.crl" -destination "C:\windows\system32\CertSrv\CertEnroll\" -force -ea stop
    copy-item -path "$root_folder\Root\*.crt" -destination "C:\windows\system32\CertSrv\CertEnroll\" -force -ea stop
}
Catch{
    write-warning "Unable to copy files from $root_folder to CertEnroll folder."
    return
}
#Publish CRL to AD. This is obsolete.
if ($dspublish) {
    $files = gci "$root_folder\Root\*.crl"
    foreach ($file in $files) {
        Try{
            invoke-command -ScriptBlock {cmd /c "certutil -dspublish -f $($file.fullname)"} -ea stop | out-null
        }
        Catch{
            write-warning "Unable to publish CRLs to AD"
        }
    }
}
#Launch a maintenance to propagate the new CRL
if ($no_maintenancetask) {
    #OK
}
Else{
    Try{
        Start-ScheduledTask -TaskName $maintenance_task -ea stop | out-null
        write-host "Maintenance task has been launched."
    }
    Catch{
        write-warning "Unable to launch scheduled task $maintenance_task."
        return
    }
}
write-host "Job completed."