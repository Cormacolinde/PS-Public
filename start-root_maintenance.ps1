#This script will generate a new CRL, copy it to the correct location, create a backup of the CA database and copy all files to a USB key or file share.
#Specify either the usb switch and usb drive letter OR a SubCA FQDN (you can also specify a different share path on the SubCA server)

[CmdletBinding(DefaultParameterSetName = 'smb')]
Param(
    [parameter(Mandatory=$true)]
    [string]$backupkey,
    $root_folder = "C:\CA",
    [parameter(Mandatory=$true,ParameterSetName='usb')]
    [switch]$usb,
    [parameter(Mandatory=$true,ParameterSetName='usb')]
    [string]$usbdrive,
    [parameter(Mandatory=$true,ParameterSetName='smb')]
    [string]$subcafqdn,
    [parameter(Mandatory=$false,ParameterSetName='smb')]
    $Share_folder = "CA"
)

#Create folders
$local_path = "$root_folder\Root"
$Share_path = "\\$subcafqdn\$Share_folder"
mkdir $local_path -ErrorAction Ignore
#Check if USB drive exists, mount drive if SMB
if ($usb) {
    #Check basic usb path
    $usbpath = "$usbdrive`:\"
    Try{
        test-path $usbpath -ea stop | out-null
    }
    Catch{
        write-warning "USB drive $usbdrive could not be accessed."
        return
    }
    #Define destination path
    $dest_path = $usbpath+"CA\Root"
}
Else {
    #Make sure no drive is mounted
    Remove-PSDrive -Name "K" -ErrorAction SilentlyContinue
    #Obtain domain account creds
    write-host 'Enter the credentials for the service account.'
    $subca_creds = Get-Credential
    #Mount CA share on drive K:
    Try{
        New-PSDrive -Name "K" -PSProvider FileSystem -Root $Share_path -Credential $subca_creds -ea stop | out-null
    }
    Catch{
        write-warning "Unable to mount $Share_path. Exiting."
        return
    }
    #Check if mount is succesful
    if (test-path "K:") {
        #OK
    }
    Else {
        write-warning "Unable to mount $Share_path. Exiting."
        return
    }
    #Define destination path
    $dest_path = "K:\"
}

#Generate a new CRL
Try{
    invoke-command -ScriptBlock {cmd /c "certutil -crl"} -ea stop | out-null
}
Catch{
    write-warning "Unable to generate a new crl."
    return
}
#Check if CRL was updated
#Define the correct cutoff date for new crl
$date_6months = $(get-date).AddDays(182)
#Get all CRLs
$crls = @(gci "C:\windows\system32\certsrv\CertEnroll\*.crl")
#Check each of them for expiration date
foreach ($crl in $crls) {
    #get CRL nextupdate info
    Try{
        [datetime]$nextupdate = (Invoke-Command -scriptblock {cmd /c "certutil -dump $($args[0])"} -ArgumentList "$($crl.fullname)" -ea stop | select-string "NextUpdate").ToString().replace(" NextUpdate: ","")
    }
    Catch{
        write-warning "Unable to parse CRL $($crl.fullname)"
        return
    }
    #Check date
    if ($nextupdate -lt $date_6months) {
        write-warning "CRL does not appear to have been renewed."
        return
    }
}

#Copy CRLs to the CA folder
Try{
    copy-item "C:\windows\system32\CertSrv\CertEnroll\*.*" $local_path -force -ea stop
}
Catch{
    write-warning "Unable to copy CRL files to $local_path"
    return
}
#Backup the CA
Try{
    invoke-command -ScriptBlock {cmd /c "certutil -f -p $backupkey -backup $($args[0])"} -ArgumentList "$local_path\Backup" -ea stop | out-null
}
Catch{
    write-warning "Unable to complete Root CA backup"
    return
}
#Check backup date and make sure it's within the last 5 minutes
Try{
    $backup = get-item "$local_path\Backup\*.p12" -ea stop
}
Catch{
    write-warning "No backup file found"
    return
}
if ($backup.lastwritetime -lt $(get-date).AddMinutes(-5)) {
    write-warning "Backup appears to have failed as it is not up to date."
    return
}
#Backup Registry entries
Try{
    invoke-command -ScriptBlock {cmd /c "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration $local_path\Backup\Configuration.reg /y"} | out-null
}
Catch{
    write-warning "Unable to backup registry settings."
}
#Check registry backup date and make sure it's within the last 5 minutes
Try{
    $backup = get-item -path "$local_path\Backup\Configuration.reg" -ea stop
}
Catch{
    write-warning "No registry backup file found"
    return
}
if ($backup.lastwritetime -lt $(get-date).AddMinutes(-5)) {
    write-warning "Registry backup appears to have failed as it is not up to date."
    return
}
#Copy all files to the dest path
Try{
    copy-item -path $local_path -destination $dest_path -force -Recurse -ea stop
}
Catch{
    write-warning "Copy to $dest_path failed."
    return
}
#Unmount SMB drive or eject USB drive
if ($usb) {
    Try{
        $driveEject = New-Object -comObject Shell.Application -ea stop
        $driveEject.Namespace(17).ParseName("$usbdrive`:\").InvokeVerb("Eject") | out-null
    }
    Catch{
        write-warning "Unable to eject USB drive please do so manually"
    }
}
Else{
    Remove-PSDrive -Name "K" -ErrorAction SilentlyContinue
}
write-host "Job completed."