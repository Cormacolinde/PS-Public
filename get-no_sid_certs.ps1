#Try to load PSPKI module
Try{
    import-module pspki -ea stop
}
Catch{
    #PKI module not installed, try to install
    install-module pspki
    Try{
        import-module pspki -ea stop
    }
    Catch{
        write-warning "Unable to load PSPKI module"
        return
    }
}    

#Get list of AD CAs
$cas = @(get-ca)
#Check we have only one, if multikle are found comment the next line and modify the line after with the index for the correct CA
if ($cas.count -gt 1) {write-warning "Multiple CAs found, please specify one." $cas;return}
$ca = $cas[0]
$temp_path = "$env:TEMP\temp.crt"
Try{
    $certs = @((get-issuedrequest -CertificationAuthority $ca[0] -properties * -ea stop))
}
Catch{
    write-warning "Unable to get certificates from CA"
    return
}
#Get current date to check only valid certs
$today = get-date
#Check each cert
foreach ($cert in $certs) {
    #Check expiration date
    if ($cert.NotAfter -lt $today) {continue}
    #export raw cert to temp file
    $cert.rawcertificate | out-file $temp_path -Force
    #Load cert into X509 object
    $temp_cert = new-object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $temp_path
    #Check if the SID OID is present
    if (($temp_cert | select -ExpandProperty Extensions).Oid.Value -notcontains "1.3.6.1.4.1.311.25.2") {
        write-warning "Problem with cert with CN $($cert.CommonName) and thumbprint $($Cert.CertificateHash)"
        $results += $Cert.CertificateHash
    }
}

$results | out-file $env:TEMP\no_sid_certs.txt -force