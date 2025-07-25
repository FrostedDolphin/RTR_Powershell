#Desc: Lookup CSLID
function clslookup 
{
    Param([string]$clsid)
    $KEY ='HKLM:\SOFTWARE\Classes\CLSID'
    If (Test-Path $KEY\$clsid) {
       $name = (Get-ItemProperty -Path $KEY\$clsid).'(default)'
       $dll = (Get-ItemProperty -Path $KEY\$clsid\InProcServer).'(default)'
    }
    $name, $dll
}
