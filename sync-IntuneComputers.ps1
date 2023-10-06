[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Mandatory=$true)]
    [String] $TenantId,
    [Parameter(Mandatory=$true)]
    [String] $ClientId,
    [Parameter(Mandatory=$false,HelpMessage="Set this property if using a Client Secret")]
    [String] $ClientSecret,
    [Parameter(Mandatory=$false,HelpMessage="Use to specify a certificate thumbprint")]
    [String] $ClientCert,
    [parameter(Mandatory=$false,HelpMessage="Clean will delete computer accounts not found in AAD")]
    [switch]$clean,
    [Parameter(Mandatory=$true,HelpMessage="FQDN of the NDES server")]
    [string]$NDESServer,
    [Parameter(Mandatory=$true,HelpMessage="orgUnit must contain the DN of the OU where to create dummy computer accounts")]
    $orgUnit
)

#Load and install required modules
#AD Module
Try{
    import-module -Name ActiveDirectory -ea Stop
}
Catch{
    #Module not found, let's try installing it
    write-host "Attempting to install Active Directory module for AD and CA access."
    Try{
        #Install module
        Install-WindowsFeature -Name RSAT-AD-PowerShell -ea stop | out-null
        import-module -name ActiveDirectory -ea stop
    }
    Catch{
        #Try Windows 10/11 option
        Try{
            Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ea stop | out-null
            import-module -name ActiveDirectory -ea stop
        }
        Catch{
            #Unable to install module, give a warning and quit.
            write-warning "PowerShell module ActiveDirectory not found. Please install it manually. If it was just installed, you may have to relaunch all PowerShell windows to load the module."
            return
        }
    }
}
#Install CA Management tools
Try{
    #If Windows Server
    $rsat_adcs_state = (Get-WindowsFeature -Name RSAT-ADCS-Mgmt -ea stop).InstallState
    if ($rsat_adcs_state -ne 'Installed'){
        Try{
            write-host "Attempting to install AD Certificate Services Administration tools."
            install-windowsfeature -name RSAT-ADCS-Mgmt -ea stop | out-null
        }
        Catch{
            #Unable to install module, give a warning and quit.
            write-warning "Unable to install Windows Server Feature for AD Certificate Services Administration"
            return
        }
    }
}
Catch{
    #Try Windows 10/11 option
    $rsat_adcs_state = (get-WindowsCapability -online -Name 'Rsat.CertificateServices.Tools~~~~0.0.1.0').state
    if ($rsat_adcs_state -ne 'Installed') {
        Try{
            write-host "Attempting to install AD Certificate Services Administration tools."
            Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0 -ea stop | out-null
        }
        Catch{
            #Unable to install module, give a warning and quit.
            write-warning "Unable to install Windows Server Feature for AD Certificate Services Administration"
            return
        }
    }
}
#MSGraph module
Set-Variable -Name MaximumVariableCount -Value 8192 -Scope Global
Set-Variable -Name MaximumFunctionCount -Value 8192 -Scope Global
Try{
    import-module -Name Microsoft.Graph.Authentication -MinimumVersion '2.4.0' -ea Stop
    import-module -Name Microsoft.Graph.DeviceManagement -MinimumVersion '2.4.0' -ea Stop
}
Catch{
    #Module not found, let's try installing it
    write-host "Attempting to install Microsoft.Graph module for Azure AD access."
    Try{
        #Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #Install NuGet
        Install-PackageProvider NuGet -Force -ea stop | out-null
        #Trust repository
        Set-PSRepository PSGallery -InstallationPolicy Trusted -ea stop
        #Install module
        install-module -name Microsoft.Graph -Repository PSGallery -MinimumVersion '2.4.0' -Scope AllUsers -force -ea stop
        import-module -name Microsoft.Graph -ea stop
    }
    Catch{
        #Unable to install module, give a warning and quit.
        write-warning "PowerShell module Microsoft.Graph not found. Please install it manually from https://www.powershellgallery.com/packages/Microsoft.Graph/"
        return
    }
}
#PSPKI module
Try{
    import-module -Name PSPKI -ea Stop -MinimumVersion '4.0.0'
}
Catch{
    #Module not found, let's try installing it
    write-host "Attempting to install PSPKI module to manipualte certificates."
    Try{
        #Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #Install NuGet
        Install-PackageProvider NuGet -Force -ea stop | out-null
        #Trust repository
        Set-PSRepository PSGallery -InstallationPolicy Trusted -ea stop
        #Install module
        install-module -name PSPKI -Repository PSGallery -MinimumVersion '4.0.0' -Scope AllUsers -force -ea stop
        import-module -name PSPKI -ea stop
    }
    Catch{
        #Unable to install module, give a warning and quit.
        write-warning "PowerShell module PSPKI not found. Please install it manually from https://www.powershellgallery.com/packages/PSPKI/"
        return
    }
}
<#Windows AutopilotIntune module
Try{
    import-module -Name WindowsAutoPilotIntune -ea Stop -MinimumVersion '5.6'
}
Catch{
    #Module not found, let's try installing it
    write-host "Attempting to install WindowsAutoPilotIntune module for Azure AD access."
    Try{
        #Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #Install NuGet
        Install-PackageProvider NuGet -Force -ea stop | out-null
        #Trust repository
        Set-PSRepository PSGallery -InstallationPolicy Trusted -ea stop
        #Install module
        install-module -name WindowsAutoPilotIntune -Repository PSGallery -MinimumVersion '5.6' -Scope AllUsers -force -ea stop
        import-module -name WindowsAutoPilotIntune -ea stop
    }
    Catch{
        #Unable to install module, give a warning and quit.
        write-warning "PowerShell module WindowsAutoPilotIntune not found. Please install it manually from https://www.powershellgallery.com/packages/WindowsAutoPilotIntune/"
        return
    }
}
#>
#region Functions
function Reverse-CertificateIssuer {
    [CmdletBinding()]
    Param(
            [Parameter(Position = 0, mandatory = $true)]
            [string] $CertIssuer)

    #Split the issuer DN into parts by comma
    $CertIssuernospaces = $CertIssuer -replace ',\s',','
    $splitresults =$CertIssuernospaces -split "," -ne ''

    #Reverse the DN to create the reverse issuer
    $reversed =$splitresults[-1.. - $splitresults.Length] -join ', '

    $reversed.trimstart()

    #end function
}
function Reverse-CertificateSerialNumber {
    [CmdletBinding()]
    Param(
    [Parameter(Position=0,mandatory=$true)]
    [string] $CertSerialNumber)

    #Split the string into two characters to represent the byte encoding
    $splitresults = $CertSerialNumber  -split '(..)' -ne ''

    #Take the byte split serial number and reverse the digits to get the correct cert formatting
    $splitresults[-1..-$splitresults.Length] -join ''

    #end function
}
#endregion

#Init vars
Try{
    $domaindn = (get-addomain -ea stop).DistinguishedName
    $domaindns = (get-addomain -ea stop).DNSRoot
}
Catch{
    write-warning "Unable to get domain information."
    return
}
$now = get-date

# Connect to MSGraph with application credentials
#If a client secret was specified, use that
if ($ClientSecret) {
    Try{
        Connect-MSGraphApp -Tenant $TenantId -AppId $ClientId -AppSecret $ClientSecret -ea stop
        write-host -ForegroundColor Yellow "Logged in to MS Graph using Client Secret specified on the command line. This is not secure, please switch to cert authentication."
    }
    Catch{
        write-warning "Unable to connect to MS Graph using specified information."
    }
}
Else{
    #Check if thumbprint was specified
    if ($ClientCert) {
        #Check if cert exists
        Try{
            gci "Cert:\CurrentUser\My\$clientcert" -ea stop
        }
        Catch{
            write-warning "Specified client cert does not exist."
            return
        }
        #try to connect using cert
        Try{
            Connect-MgGraph -ClientID $ClientId -TenantId $TenantId -CertificateThumbprint $ClientCert -nowelcome -ea stop
            write-host "Logged in to MS Graph using specified cert."
        }
        Catch{
            write-warning "Connection unsuccessful using specified MS Graph information and cert thumbprint."
            return
        }
    }
    Else{
        Try{
            Connect-MgGraph -ClientID $ClientId -TenantId $TenantId -CertificateSubjectName "CN=$env:USERNAME" -nowelcome -ea stop
            write-host "Logged in to MS Graph using cert available in local store."
        }
        Catch{
            write-warning "Connection unsuccessful using specified MS Graph information and available cert."
            return
        }
    }
}

# Pull latest Intune device information
write-host "Retrieving Intune Devices."
Try{
    $Intunedevices = @(Get-MgDeviceManagementManagedDevice -ea stop | where-object {$_.DeviceEnrollmentType -eq 'windowsAzureADJoin'})
}
Catch{
    write-warning "Unable to get list of intune devices. Check that your MS Graph app has User.Read.All, Device.Read.All and DeviceManagementManagedDevices.Read.All rights."
    return
}

# Create new AAD-only device objects in Intune while skipping already existing computer objects
foreach ($Device in $Intunedevices) {
    if (Get-ADComputer -Filter "Name -eq ""$($Device.AzureAdDeviceId)""" -SearchBase $orgUnit -ErrorAction SilentlyContinue) {
        #Write-Output "Skipping $($Device.AzureAdDeviceId) because it already exists. "
    } else {
        # Create new AD computer object
        try {
            New-ADComputer -Name "$($Device.AzureAdDeviceId)" -SAMAccountName "$($Device.AzureAdDeviceId.Substring(0,15))`$" -ServicePrincipalNames "HOST/$($Device.AzureAdDeviceId)" -Path $orgUnit -DNSHostName "$($Device.AzureAdDeviceId).$domaindns" -ea stop
            Write-Output "Computer object created for ($($Device.AzureAdDeviceId))."
        } catch {
            Write-Error "Error creating computer account for ($($Device.AzureAdDeviceId))."
        }
    }
}

# Reverse the process and remove any dummmy computer objects in AD that are no longer in Intune
$DummyDevices = Get-ADComputer -Filter * -SearchBase $orgUnit | Select-Object Name, SAMAccountName
foreach ($DummyDevice in $DummyDevices) {
    if ($Intunedevices.AzureAdDeviceId -contains $DummyDevice.Name) {
        # Write-Output "$($DummyDevice.Name) exists in Intune."
    } else {
        if ($clean) {
            Write-Output "AD Object $($DummyDevice.Name) does not exist in Intune. Removing..."
            Remove-ADComputer -Identity $DummyDevice.SAMAccountName -Confirm:$False -WhatIf
        }
        Else{
            Write-Output "$($DummyDevice.Name) does not exist in AAD. Object not removed since -clean switch not specified."
        }
    }
}

#Retrieve CAs
write-host "Retrieving Certificate Authorities."
$CAs = @(Get-CA)
#Retrieve info from NDES Server
#Check connectivity
Try{
    invoke-command -ScriptBlock {Get-ChildItem .} -ComputerName $NDESServer -ea stop | out-null
}
Catch{
    write-warning "Unable to connect to NDES server, unable to bind certificates."
    return
}
#Get templates
$CertTemplates = @()
Try{
    $CertTemplates += invoke-command -ScriptBlock {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\').SignatureTemplate} -ComputerName $NDESServer -ea stop
    $CertTemplates += invoke-command -ScriptBlock {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\').EncryptionTemplate} -ComputerName $NDESServer -ea stop
    $CertTemplates += invoke-command -ScriptBlock {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\').GeneralPurposeTemplate} -ComputerName $NDESServer -ea stop
}
Catch{
    write-warning "Unable to retrieve templates from NDES server"
    return
}
#Get serviceaccount
Try{
    $NDESServiceAccount = invoke-command -ScriptBlock {(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\PKIConnectorSvc').ObjectName} -ComputerName $NDESServer -ea stop
}
Catch{
    write-warning "Unable to determine NDES Service Account from remote registry."
    return
}

# Retrieve all Certificate Templates and their OIDs
#Write-Host("Retrieving Certificate templates.")
Try{
    $CertTemplateOIDs = $CertTemplates | ForEach-Object {
        (Get-CertificateTemplate -Name $_ -ea stop).oid.Value
    }
}
Catch{
    write-warning "Unable to retrieve Certificate Templates information."
    return
}

$certs = @()
$revokedcerts = @()
foreach ($CertAuthority in $CAs) {
    # Retrieve all certificates that match our template
    Write-Host("Retrieving Certificates.")
    Try{
        $certs += Get-IssuedRequest -CertificationAuthority $CertAuthority -Filter "NotAfter -ge $(Get-Date)" -Property DistinguishedName,RawCertificate | Where-Object {$_.CertificateTemplate -in $CertTemplateOIDs}
    }
    Catch{
        write-warning "Unable to retrieve certificates from CA $($certauthority.Name). Make sure you have Read access to this CA."
    }
}

if ($certs.count -eq 0) {
    write-warning "No certificates found."
    return
}

Write-Host("Processing Certificates.")
foreach($cert in ($certs | where request.requestername -eq $NDESServiceAccount | sort requestid)){
    #Check certificate validity
    #Expiration
    if ($cert.NotAfter -lt $now) {
        #Cert expired
        continue
    }
    #retrieve AD object
    #Check for computer object
    $requester = $cert.'CommonName'
    $ADObject = Get-ADObject -Filter { dnsHostName -eq $requester} -Properties 'altSecurityIdentities' -ErrorAction SilentlyContinue
    #Check for user object if no computer found
    if (!$ADObject) {
        $requester = ($cert.Properties | where-object {$_.Key -eq 'DistinguishedName'}).Value.Replace("`"","")
        $ADObject = Get-ADObject -Filter { distinguishedName -eq $requester} -Properties 'altSecurityIdentities' -ErrorAction SilentlyContinue
    }
    
    if (!$ADObject) {
        write-warning "No object found for certificate $($cert.RequestID) - $requester"
        continue
    }

    # Build CA Cert Subject
    $certissuer = ($cas | where-object {$_.ConfigString -eq $cert.ConfigString}).Certificate.Subject
    $CACertSubject = (Reverse-CertificateIssuer -CertIssuer $certissuer).Replace(" ","")

    # Build Serial Numbers
    $CertForwardSN = $cert.SerialNumber
    $CertBackwardSN = (Reverse-CertificateSerialNumber -CertSerialNumber $CertForwardSN).ToUpper()

    # Build X509 Address
    $X509IssuerSerialNumber = "X509:<I>$CACertSubject<SR>$CertBackwardSN"

    # Check if the attribute is already set, otherwise initialize array
    if(!($altIDs = $ADObject.'altSecurityIdentities')){
        $altIDs = @()
    }

    # Check if our X509IssuerSerialNumber is already in it
    if($X509IssuerSerialNumber -notin $altIDs){
        # It is not, add it
        Write-Host("[$($cert.RequestID) - $requester] Adding X509: `"$X509IssuerSerialNumber`"")
        $altIDs += $X509IssuerSerialNumber

	    # Write out the AD Object
	    Try{
            $ADObject | Set-ADObject -Replace @{'altSecurityIdentities' = $altIDs} -ea stop
        }
        Catch{
            write-warning "Unable to write altSecurityIdentities for object $($ADObject.distinguishedname)."
        }
    }
}