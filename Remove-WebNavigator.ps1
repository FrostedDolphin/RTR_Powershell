# Created by Tudor 
[CmdletBinding()]            
Param(            
    [string]$UserAccount           
)
$UserObject = [System.Security.Principal.NTAccount]::new($DomainName, $UserAccount)
$out = $UserObject.Translate([System.Security.Principal.SecurityIdentifier])
$SIDValue = $out.Value
Stop-Process -Name "webnavigatorbrowser" -Force
schtasks.exe /delete /tn "\BetterCloudSolutions_$SIDValue\WebNavigatorBrowser-StartAtLogin" /f
Remove-Item -Force -Recurse -Path "C:\Users\$UserAccount\AppData\Local\WebNavigatorBrowser\"
