Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications" -Recurse 
New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications" | out-null

Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System"
New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" | out-null

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" -Name "DeleteUserAppContainersOnLogoff" -Value "1" -PropertyType "DWORD" -ea SilentlyContinue | out-null

$FWInboundRules       = Get-NetFirewallRule -Direction Inbound |Where {$_.Owner -ne $Null} | sort Displayname, Owner 
$FWInboundRulesUnique = Get-NetFirewallRule -Direction Inbound |Where {$_.Owner -ne $Null} | sort Displayname, Owner -Unique 

Write-Host "# inbound rules         : " $FWInboundRules.Count
Write-Host "# inbound rules (Unique): " $FWInboundRulesUnique.Count 

if ($FWInboundRules.Count -ne $FWInboundRulesUnique.Count) {
Write-Host "# rules to remove       : " (Compare-Object -referenceObject $FWInboundRules  -differenceObject $FWInboundRulesUnique).Count
Compare-Object -referenceObject $FWInboundRules  -differenceObject $FWInboundRulesUnique   | select -ExpandProperty inputobject |Remove-NetFirewallRule }

$FWOutboundRules       = Get-NetFirewallRule -Direction Outbound |Where {$_.Owner -ne $Null} | sort Displayname, Owner 
$FWOutboundRulesUnique = Get-NetFirewallRule -Direction Outbound |Where {$_.Owner -ne $Null} | sort Displayname, Owner -Unique 
Write-Host "# outbound rules         : : " $FWOutboundRules.Count
Write-Host "# outbound rules (Unique): " $FWOutboundRulesUnique.Count 
if ($FWOutboundRules.Count -ne $FWOutboundRulesUnique.Count)  {
Write-Host "# rules to remove       : " (Compare-Object -referenceObject $FWOutboundRules  -differenceObject $FWOutboundRulesUnique).Count
Compare-Object -referenceObject $FWOutboundRules  -differenceObject $FWOutboundRulesUnique   | select -ExpandProperty inputobject |Remove-NetFirewallRule}

$FWConfigurableRules       = Get-NetFirewallRule -policystore configurableservicestore |Where {$_.Owner -ne $Null} | sort Displayname, Owner 
$FWConfigurableRulesUnique = Get-NetFirewallRule -policystore configurableservicestore |Where {$_.Owner -ne $Null} | sort Displayname, Owner -Unique 
Write-Host "# service configurable rules         : " $FWConfigurableRules.Count
Write-Host "# service configurable rules (Unique): " $FWConfigurableRulesUnique.Count 
if ($FWConfigurableRules -eq $null) {return}
if ($FWConfigurableRules.Count -ne $FWOutboundRulesUnique.Count)  {
Write-Host "# rules to remove                    : " (Compare-Object -referenceObject $FWConfigurableRules  -differenceObject $FWConfigurableRulesUnique).Count
Compare-Object -referenceObject $FWConfigurableRules  -differenceObject $FWConfigurableRulesUnique   | select -ExpandProperty inputobject |Remove-NetFirewallRule}