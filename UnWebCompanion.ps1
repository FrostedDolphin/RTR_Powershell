$badreg = 'Registry::HKU\*\Software\Microsoft\Windows\CurrentVersion\Run'
$malfiledir = "C:\Program Files (x86)\Lavasoft\Web Companion\", "C:\Users\*\AppData\Roaming\BBWC\", "C:\Users\*\AppData\Roaming\Browser Extension\updater.exe"
#Idea:
#$updaterhash="<SHA-256>"
#get hash of updater.exe and delete file by known bad hash

echo '---------------------------------------';

echo 'Registry Run Persistence Being Removed:'

echo '---------------------------------------'; 
Foreach ($reg in $badreg)
{
$regoutput1 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCStartup'} | select -exp Property ;
$regoutput2 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCUpate'} | select -exp Property ;
$regoutput3 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEStartup'} | select -exp Property ;
$regoutput4 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEUpdater'} | select -exp Property ;
$regoutput5 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'Web Companion'} | select -exp Property ;


$regpath1 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCStartup'} | select -exp Name ;
$regpath2 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCUpate'} | select -exp Name ;
$regpath3 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEStartup'} | select -exp Name ;
$regpath4 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'WCEUpdater'} | select -exp Name ;
$regpath5 = gi -path $reg -ea silentlycontinue | ? {$_.Property -like 'Web Companion'} | select -exp Name ;

Foreach($prop1 in $regoutput1){
If ($prop1 -like 'WCStartup') {"$regpath1 value: $prop1 `n"
reg delete $regpath1 /v $prop1 /f
}}

Foreach($prop2 in $regoutput2){
If ($prop2 -like 'WCUpate') {"$regpath2 value: $prop2 `n"
reg delete $regpath2 /v $prop2 /f
}}

Foreach($prop3 in $regoutput3){
If ($prop3 -like 'WCEStartup') {"$regpath3 value: $prop3 `n"
reg delete $regpath3 /v $prop3 /f
}}

Foreach($prop4 in $regoutput4){
If ($prop4 -like 'WCEUpdater') {"$regpath4 value: $prop4 `n"
reg delete $regpath4 /v $prop4 /f
}}

Foreach($prop5 in $regoutput5){
If ($prop5 -like 'Web Companion') {"$regpath5 value: $prop5 `n"
reg delete $regpath5 /v $prop5 /f
}}
    
}

echo '-----------------------------------';

echo 'Files in BBWC Folder Being Removed:'

echo '-----------------------------------'; 

get-childitem -Recurse $malfiledir
remove-Item $malfiledir -Recurse -Force

echo '----------------------------------------------------'; 
echo "WebCompanion files eliminated." 
echo "remove related msi file(s) and other bundled adware."
echo "Heres a list of Chrome extensions to review.."
echo '----------------------------------------------------'; 
echo `n

#check for browser extension names in Chrome
function ConvertFrom-Json20([object] $item)
{
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return ,$ps_js.DeserializeObject($item)
}
 
$output = 'User, Extension Name, Version' + [System.Environment]::NewLine
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
        }
    }
}
$output
