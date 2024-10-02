$badreg = 'Registry::HKU\*\Software\Microsoft\Windows\CurrentVersion\Run'
$malfiledir = "C:\Program Files (x86)\Lavasoft\Web Companion\", "C:\Users\*\AppData\Roaming\BBWC\", "C:\Users\*\AppData\Roaming\Browser Extension\updater.exe", "C:\Users\*\AppData\Roaming\Lavasoft\Web Companion\"
#$updaterhash="<SHA-256>"
#get hash of updater.exe and delete file by known bad hash


Write-Output "Removed:"

Foreach ($reg in $badreg)
{
    $itemsFound = $false

    $regoutput1 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCStartup'} | select -exp Property ;
    $regoutput2 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCUpate'} | select -exp Property ;
    $regoutput3 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEStartup'} | select -exp Property ;
    $regoutput4 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEUpdater'} | select -exp Property ;
    $regoutput5 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'Web Companion'} | select -exp Property ;
    $regoutput6 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'Ad-Aware Search Companion'} | select -exp Property ;

    $regpath1 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCStartup'} | select -exp Name ;
    $regpath2 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCUpate'} | select -exp Name ;
    $regpath3 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEStartup'} | select -exp Name ;
    $regpath4 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEUpdater'} | select -exp Name ;
    $regpath5 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'Web Companion'} | select -exp Name ;
    $regpath6 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'Ad-Aware Search Companion'} | select -exp Name ;

    Foreach($prop1 in $regoutput1){
        If ($prop1 -like 'WCStartup') {
            Write-Output "$regpath1 value: $prop1"
            reg delete $regpath1 /v $prop1 /f
            $itemsFound = $true
        }
    }

    Foreach($prop2 in $regoutput2){
        If ($prop2 -like 'WCUpate') {
            Write-Output "$regpath2 value: $prop2"
            reg delete $regpath2 /v $prop2 /f
            $itemsFound = $true
        }
    }

    Foreach($prop3 in $regoutput3){
        If ($prop3 -like 'WCEStartup') {
            Write-Output "$regpath3 value: $prop3"
            reg delete $regpath3 /v $prop3 /f
            $itemsFound = $true
        }
    }

    Foreach($prop4 in $regoutput4){
        If ($prop4 -like 'WCEUpdater') {
            Write-Output "$regpath4 value: $prop4"
            reg delete $regpath4 /v $prop4 /f
            $itemsFound = $true
        }
    }

    Foreach($prop5 in $regoutput5){
        If ($prop5 -like 'Web Companion') {
            Write-Output "$regpath5 value: $prop5"
            reg delete $regpath5 /v $prop5 /f
            $itemsFound = $true
        }
    }

    Foreach($prop6 in $regoutput6){
        If ($prop6 -like 'Ad-Aware Search Companion') {
            Write-Output "$regpath6 value: $prop6"
            reg delete $regpath6 /v $prop6 /f
            $itemsFound = $true
        }
    }

    if (-not $itemsFound) {
        Write-Output "no reg items"
    }
}

$stasks = schtasks /query /fo csv /v | convertfrom-csv | ?{$_.TaskName -like 'WC* ScheduledTask'} | select -exp TaskName


if ($stasks){

Foreach ($task in $stasks){

Write-Output "SchTask- "$task

schtasks /delete /tn $task /F

}

}

else {Write-Output"No Scheduled Tasks"};

$files = get-childitem -Recurse $malfiledir -ea silentlycontinue

if ($files) {
    remove-Item $malfiledir -Recurse -Force -ea silentlycontinue
} else {
    Write-Output "No files"
}

Write-Output "Chrome Extensions:"
#check for browser extension names
function ConvertFrom-Json20([object] $item)
{
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return ,$ps_js.DeserializeObject($item)
}
 
$output = 'User, Extension Name, Version' + [System.Environment]::NewLine
$extensionsFound = $false
$users = Get-ChildItem c:\users | ?{ $_.PSIsContainer }
foreach ($user in $users)
{
    $extpath = 'c:\users\' + $user  + '\appdata\local\Google\Chrome\User Data\Default\Extensions\*\*\manifest.json'
    $extensions = Get-ChildItem $extpath -ErrorAction SilentlyContinue
    foreach ($extension in $extensions)
    {
        $content = Get-Content $extension.FullName -Raw
        $json = $content | ConvertFrom-JSON
        if (-Not ($json.name -like '__msg_*'))
        {  
            $output += $user.Name + ', ' + $json.name + ', ' + $json.version + [System.Environment]::NewLine
            $extensionsFound = $true
        }
    }
}

if (-not $extensionsFound) {
    Write-Output "no extensions"
} else {
    $output
}
