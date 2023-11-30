#This script will copy the CRL and AIA certs to the public web server, using either SMB (for Windows servers) or SSH (for Linux servers)
#It will also complete a backup of the CA database
#SMB mode requires a login, SSH mode requires a private SSH key
[CmdletBinding(DefaultParameterSetName = 'smb')]
Param (
    [parameter(Mandatory=$true,HelpMessage="Protocol to use (SSH or SMB)")]
    [ValidateSet("ssh","smb")]
    [string]$protocol,
    [parameter(HelpMessage="Base folder where files are kept")]
    [string]$ca_folder="C:\CA",
    [parameter(HelpMessage="Share path to access backup server.")]
    [string]$backup_path,
    [parameter(Mandatory=$true,HelpMessage="Server name to copy files to")]
    [string]$serverfqdn,
    [parameter(HelpMessage="Sets the remote path for SSH servers",ParameterSetName='ssh')]
    [string]$serverpath="/var/www/html/certenroll/",
    [parameter(HelpMessage="Sets the remote share for SMB servers",ParameterSetName='smb')]
    [string]$servershare="certenroll",
    [parameter(HelpMessage="Use this switch to clear all credentials and force asking for them")]
    [switch]$resetcredentials,
    [parameter(Mandatory=$false,HelpMessage="SSH username",ParameterSetName='ssh')]
    $ssh_username,
    [parameter(HelpMessage="This is the folder that should contain all CRL and AIA source files.")]
    $crl_folder = "C:\Windows\system32\CertSrv\CertEnroll"
)

#Test if main CA path exists/is accessible
if (test-path $ca_folder) {
    $root_folder = $ca_folder
    $local_path = "$root_folder\Sub"
}
Else{
    write-warning "CA folder not found or inaccessible."
    return
}

#Set cred file paths
$creds_publicca_file = "$root_folder\creds.xml"
$creds_publiccassh_ppk = "$root_folder\ssh.ppk"
$creds_publiccassh_pass = "$root_folder\ssh.key"
$creds_backup_file = "$root_folder\creds_backup.xml"
$backup_key_file = "$root_folder\backupkey.cred"

#Delete all credentials if resetcredentials is set
if ($resetcredentials) {
    remove-item -Path $creds_publicca_file -Force -ea SilentlyContinue
    remove-item -Path $creds_publiccassh_ppk -Force -ea SilentlyContinue
    remove-item -Path $creds_publiccassh_pass -Force -ea SilentlyContinue
    remove-item -Path $creds_backup_file -Force -ea SilentlyContinue
    remove-item -Path $backup_key -Force -ea SilentlyContinue
}

#Initialize as required for the selected connectivity protocol
switch ($protocol)
{
    'smb' {
        #Test if Windows server is accessible using SMB
        $OriginalProgressPreference = $Global:ProgressPreference
        $Global:ProgressPreference = 'SilentlyContinue'
        if (Test-NetConnection -ComputerName $serverfqdn -Port 445 -InformationLevel Quiet) {
            $hostname = $serverfqdn
            $Global:ProgressPreference = $OriginalProgressPreference
        }
        Else{
            write-warning "Server $serverfqdn is not accessible on port 445"
            $Global:ProgressPreference = $OriginalProgressPreference
            return
        }
        #Get credentials for SMB access
        if (test-path $creds_publicca_file) {
            $creds_publicca = Import-Clixml -Path $creds_publicca_file
            write-host "Credentials for $serverfqdn were loaded from file."
        }
        Else {
            Add-Type -AssemblyName PresentationCore,PresentationFramework
            $ButtonType = [System.Windows.MessageBoxButton]::OK
            $MessageboxTitle = “Windows Credentials”
            $Messageboxbody = “Please enter credentials for access to the $serverfqdn server.”
            $MessageIcon = [System.Windows.MessageBoxImage]::Information
            [System.Windows.MessageBox]::Show($Messageboxbody,$MessageboxTitle,$ButtonType,$messageicon)
            $creds_publicca = Get-Credential -Credential $null
            if ($creds_publicca) {
                $creds_publicca | Export-Clixml -Path $creds_publicca_file
            }
            Else{
                write-warning "No credentials were entered."
                return
            }
        }
        #Set remote server path
        $Share_path = "\\$hostname\$servershare"
    }
    'ssh' {
        #In order to use WinSCP to copy files, we need to check for the module.
        Try{
            import-module -Name WinSCP -ea Stop -MinimumVersion '6.1.1.0'
        }
        Catch{
            #Module not found, let's try installing it
            write-host "Attempting to install WinSCP module for SSH access."
            Try{
                #Set TLS 1.2
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                #Install NuGet
                Install-PackageProvider NuGet -Force -ea stop | out-null
                #Trust repository
                Set-PSRepository PSGallery -InstallationPolicy Trusted -ea stop
                #Install module
                install-module -name WinSCP -Repository PSGallery -MinimumVersion '6.1.1.0' -force -ea stop
                import-module -name WinSCP -ea stop
            }
            Catch{
                #Unable to install module, give a warning and quit.
                write-warning "PowerShell module WinSCP not found, unable to connect to a Linux server. Please install it manually from https://www.powershellgallery.com/packages/WinSCP/"
                return
            }
        }
        #Test if Linux server is available using ssh
        if (Test-NetConnection -ComputerName $serverfqdn -Port 22 -InformationLevel Quiet) {
            $hostname = $serverfqdn
        }
        Else{
            write-warning "Server $serverfqdn is not accessible on port 22"
            return
        }
        #Verify we have a ssh private key file
        if (test-path -Path $creds_publiccassh_ppk) {
            #OK
        }
        Else{
            write-warning "SSH mode selected but no SSH private key was found, please save encrypted private key in PuttyGen format at $creds_publiccassh_ppk"
            return
        }
        #Verify we have a private password file and if not request password
        if (test-path $creds_publiccassh_pass) {
            $ssh_secure = Get-Content $creds_publiccassh_pass | ConvertTo-SecureString
            write-host "SSH key was loaded from file."
        }
        Else{
            Add-Type -Assembly 'System.Windows.Forms'
            Add-Type -AssemblyName System.Drawing
            $form2 = New-Object System.Windows.Forms.Form
            $form2.Text = 'Backup Password'
            $form2.Size = New-Object System.Drawing.Size(301,200)
            $form2.StartPosition = 'CenterScreen'

            $okButton2 = New-Object System.Windows.Forms.Button
            $okButton2.Location = New-Object System.Drawing.Point(113,120)
            $okButton2.Size = New-Object System.Drawing.Size(75,23)
            $okButton2.Text = 'OK'
            $okButton2.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form2.AcceptButton = $okButton2
            $form2.Controls.Add($okButton2)

            $label2 = New-Object System.Windows.Forms.Label
            $label2.Location = New-Object System.Drawing.Point(10,20)
            $label2.Size = New-Object System.Drawing.Size(280,20)
            $label2.Text = 'Please enter the SSH key file password:'
            $form2.Controls.Add($label2)

            $password2 = New-Object Windows.Forms.MaskedTextBox
            $password2.PasswordChar = '*'
            $password2.Location = New-Object System.Drawing.Point(10,40)
            $password2.Size = New-Object System.Drawing.Size(260,20)
            $form2.Controls.Add($password2)
            $form2.Topmost = $true
            $form2.Add_Shown({$password2.Select()})
            $form2.ShowDialog() | out-null

            $ssh_secure = $password2.text | ConvertTo-SecureString -AsPlainText -force
            $ssh_secure | ConvertFrom-SecureString | out-file $creds_publiccassh_pass

            $form2.Dispose()
            remove-variable password2
        }
    }
    Default {}
}

#Prepare for backup if configured
if ($backup_path) {
    #Test if Windows server is accessible using SMB
    $backup_server = [string]::Join('\', $backup_path.Split('\')[2..$($backup_path.Split('\').Length-2)])
    $OriginalProgressPreference = $Global:ProgressPreference
    $Global:ProgressPreference = 'SilentlyContinue'
    if (Test-NetConnection -ComputerName $backup_server -Port 445 -InformationLevel Quiet) {
        $backup_share = $backup_path
        #We are doing backups
        $backup_key = "$root_folder\backupkey.cred"
        $cred_backup_file = "$root_folder\creds_backup.xml"
        $backup = $true
        $Global:ProgressPreference = $OriginalProgressPreference
    }
    Else{
        write-warning "Server $backup_server is not accessible on port 445"
        $Global:ProgressPreference = $OriginalProgressPreference
        return
    }
    #Get backup server creds
    if (test-path $creds_backup_file) {
        $cred_backupshare = Import-Clixml -Path $creds_backup_file
        write-host "Credentials for $backup_server were loaded from file."
    }
    Else {
        Add-Type -AssemblyName PresentationCore,PresentationFramework
        $ButtonType = [System.Windows.MessageBoxButton]::OK
        $MessageboxTitle = “Windows Credentials”
        $Messageboxbody = “Please enter credentials for access to the $backup_server server.”
        $MessageIcon = [System.Windows.MessageBoxImage]::Information
        [System.Windows.MessageBox]::Show($Messageboxbody,$MessageboxTitle,$ButtonType,$messageicon)
        $cred_backupshare = Get-Credential -Credential $null
        if ($cred_backupshare) {
            $cred_backupshare | Export-Clixml -Path $creds_backup_file
        }
        Else{
            write-warning "No credentials were entered."
            return
        }
    }
    #get backup key
    if (test-path $backup_key_file) {
        $backupkey_secure = Get-Content $backup_key_file | ConvertTo-SecureString
        write-host "Backup key was loaded from file."
    }
    Else{
        Add-Type -Assembly 'System.Windows.Forms'
        Add-Type -AssemblyName System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Backup Password'
        $form.Size = New-Object System.Drawing.Size(301,200)
        $form.StartPosition = 'CenterScreen'

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(113,120)
        $okButton.Size = New-Object System.Drawing.Size(75,23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,20)
        $label.Size = New-Object System.Drawing.Size(280,20)
        $label.Text = 'Please enter the CA backup password:'
        $form.Controls.Add($label)

        $password = New-Object Windows.Forms.MaskedTextBox
        $password.PasswordChar = '*'
        $password.Location = New-Object System.Drawing.Point(10,40)
        $password.Size = New-Object System.Drawing.Size(260,20)
        $form.Controls.Add($password)
        $form.Topmost = $true
        $form.Add_Shown({$password.Select()})
        $form.ShowDialog()

        $backupkey_secure = $password.text | ConvertTo-SecureString -AsPlainText -force
        $backupkey_secure | ConvertFrom-SecureString | out-file $backup_key_file

        $form.Dispose()
        remove-variable password
        
    }
    #Convert backup key to string
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($backupkey_secure)
    $backupkey = [System.Runtime.InteropServices.MArshal]::PtrToStringAuto($BSTR)
}
Else{
    #No backup share
    $backup = $false
}

#Get files for replication to PublicCA server
$files = gci -path $crl_folder | where-object {($_.Name -match ".crl") -or ($_.Name -match ".crt")}
#Create temp folder
$temp_folder = "$($env:TEMP)\ScriptCertsFolder"
remove-item -Recurse -Path "$env:TEMP\ScriptCertsFolder" -force -ea SilentlyContinue
Try{
    mkdir $temp_folder -ea stop | out-null
}
Catch{
    write-warning "Unable to create clean folder in $temp_folder"
    return
}
#Copy files to temp folder
foreach ($file in $files) {
    Try{
        copy-item -Path $file.fullname -Destination $temp_folder -ea stop
    }
    Catch{
        write-warning "Unable to copy files to $($env:TEMP)\ScriptCertsFolder"
        return
    }
}

#Renew CRLs if running on CA server
if ((Get-WindowsFeature -name 'AD-Certificate').InstallState -eq 'Installed'){
    Try{
        Invoke-Command -ScriptBlock {cmd /c "certutil -CRL"} -ea stop | Out-Null
    }
    Catch{
        write-warning "Unable to republish CRL."
    }
}

#Get al CRL to be copied and check their expiry date
$CRLs = gci -path $temp_folder | where-object {($_.Name -match ".crl")}
if ($crls.count -lt 2) {
    write-warning "CRLs are missing, please review status of server."
    return
}
write-host -ForegroundColor Yellow "`r`nThese CRLs will be copied."
foreach ($crl in $crls) {
    #get CRL nextupdate info
    Try{
        $nextupdate = (Invoke-Command -scriptblock {cmd /c "certutil -dump $($args[0])"} -ArgumentList "`"$($crl.fullname)`"" -ea stop | select-string "NextUpdate").ToString()
    }
    Catch{
        write-warning "Unable to parse CRL $($crl.fullname)"
        return
    }
    #Print info
    write-host "CRL: $($crl.name) `r`n$nextupdate`r`n"
}
#pause

switch ($protocol)
{
    'smb' {
        #Mount PublicCA share using SMB
        Try{
            New-PSDrive -Name "K" -PSProvider FileSystem -Root $Share_path -Credential $creds_publicca | out-null
        }
        Catch{
            write-warning "Unable to mount $Share_path."
            return
        }
        #Make sure mount worked
        if (test-path "K:") {
            #OK
        }
        Else {
            write-warning "Unable to mount $Share_path. Exiting."
            return
        }
        #Copy files
        $files = gci $temp_folder
        foreach ($file in $files) {
            Try{
                copy-item $file.fullname $Share_path -force -ea stop
            }
            Catch{
                write-warning "Unable to copy file $($file.fullname) to $Share_path"
                Remove-PSDrive -Name "K"
                return
            }
        }
        Remove-PSDrive -Name "K"
    }
    'ssh' {
        #Create SCP session
        [pscredential]$ssh_creds = New-Object System.Management.Automation.PSCredential ($ssh_username, $ssh_secure)
        $session_options = New-WinSCPSessionOption -HostName $serverfqdn -Protocol Scp -SshPrivateKeyPath $creds_publiccassh_ppk -SecurePrivateKeyPassphrase $ssh_secure -GiveUpSecurityAndAcceptAnySshHostKey -Credential $ssh_creds
        Try{
            $session = New-WinSCPSession -SessionOption $session_options -ea stop
        }
        Catch{
            write-warning "Unable to connect SCP session to $serverfqdn"
            return
        }
        #Test path
        if (Test-WinSCPPath -WinSCPSession $session -Path "$serverpath") {
            write-host "Copying files to $serverpath on $serverfqdn."
        }
        Else{
            write-warning "Path $serverpath on $serverfqdn is not accessible."
            Close-WinSCPSession -WinSCPSession $session
            return
        }
        #Copy files
        Try{
            $files = gci $temp_folder
            foreach ($file in $files) {
                send-WinSCPItem -WinSCPSession $session -localPath $file.fullname -remotepath $serverpath -ea Stop | out-null
            }
        }
        Catch{
            write-warning "Unable to copy files to $serverpath on $serverfqdn."
            Close-WinSCPSession -WinSCPSession $session
            return
        }
        Close-WinSCPSession -WinSCPSession $session
    }
    Default {}
}
if ($backup) {
    #Backup the CA
    Try{
        invoke-command -ScriptBlock {cmd /c "certutil -f -p $backupkey -backup $($args[0])"} -ArgumentList "$local_path\Backup" -ea stop | out-null
    }
    Catch{
        write-warning "Unable to complete Sub CA backup"
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
    #Mount backup share
    Try{
        New-PSDrive -Name "G" -PSProvider FileSystem -Root $backup_share -Credential $cred_backupshare -ea stop | out-null
        #Make sure mount worked
        if (test-path "G:") {
            #Copy the backup to the backup server
            Try{
                copy-item -Path $root_folder -Destination "G:" -Recurse -Force
            }
            Catch{
                write-warning "Unable to copy $root_folder contents to $backup_path . No backup will be done."
                Remove-PSDrive -Name "G" -ea SilentlyContinue
                return
            }
            Remove-PSDrive -Name "G" -ea SilentlyContinue
        }
        Else {
            write-warning "Unable to mount $backup_share. No backup will be done."
        }
    }
    Catch{
        write-warning "Unable to mount $backup_share. No backup will be done."
    }
}

write-host "Job Completed"