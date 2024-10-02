#Desc: rewrite of remOneLaunchv2.ps1 to include error handling and outputting of artifacts found.
echo '-----------------------------';

echo 'Finding Profiles:'

echo '-----------------------------'; 

### Checking for user accounts
$users = Get-ChildItem C:\users | Select-Object name -ExpandProperty name
Write-Output "Found Users: $users"

$sids = get-item -path "Registry::hku\*" -ErrorAction SilentlyContinue | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+"
Write-Output "Found SIDs: $sids"



echo '-----------------------------';

echo 'Processes Killed:'

echo '-----------------------------'; 

### Killing the chromium/onelaunch processes
$chromiumProcesses = get-process -name chromium -ErrorAction SilentlyContinue
if ($chromiumProcesses) {
    $chromiumProcesses | ForEach-Object { Write-Output "+ $($_.Name) - ID: $($_.Id)"; $_ } | Stop-process -Force
}

$onelaunchProcesses = get-process -name onelaunch -ErrorAction SilentlyContinue
if ($onelaunchProcesses) {
    $onelaunchProcesses | ForEach-Object { Write-Output "+ $($_.Name) - ID: $($_.Id)"; $_ } | Stop-Process -Force
}

$onelaunchtrayProcesses = get-process -name onelaunchtray -ErrorAction SilentlyContinue
if ($onelaunchtrayProcesses) {
    $onelaunchtrayProcesses | ForEach-Object { Write-Output "+ $($_.Name) - ID: $($_.Id)"; $_ } | Stop-Process -Force
}
sleep 1



echo '-----------------------------';

echo 'Directories Being Removed:'

echo '-----------------------------'; 

### Deleting OneLaunch directories
foreach ($user in $users) {
    if ($user -ne "Public") {
        $result = Test-Path -path "C:\Users\$user\AppData\Local\OneLaunch"
        if ($result -eq "True") {
            $test += $user
        } else {
            continue
        }
        echo "Removing: C:\Users\$user\AppData\Local\OneLaunch"
        rm "C:\Users\$user\AppData\Local\OneLaunch" -Force -Recurse -ErrorAction SilentlyContinue

        echo "Trying for $user"

        ### Adding other file paths to be deleted
        $paths = @(
            "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneLaunch*.lnk",
            "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneLaunch",
            "C:\Users\$user\Desktop\Onelaunch Software.exe",
            "C:\Users\$user\Desktop\Onelaunch Software.lnk",
            "C:\Users\$user\Desktop\OneLaunch.lnk",
            "C:\Users\$user\Downloads\OneLaunch - *"
        )

        foreach ($path in $paths) {
            if (Test-Path -path $path) {
                echo "+ $path"
                rm $path -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
    }
}



echo '-----------------------------';

echo 'Registry Items Being Removed:'

echo '-----------------------------'; 

### Removing registry keys
foreach ($sid in $sids){
    if ($sid -notlike "*_Classes") {
        $paths = @(
            "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run\OneLaunch*",
            "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run\GoogleChromeAutoLaunch_*",
            "Registry::$sid\Software\OneLaunch",
            "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\{4947c51a-26a9-4ed0-9a7b-c21e5ae0e71a}_is1"
        )

        foreach ($path in $paths) {
            if (Test-Path -path $path) {
                echo "+ $path"
                Remove-Item -path $path -ErrorAction SilentlyContinue
            }
        }

        $sid = [string]$sid
        $sid = $sid.replace("HKEY_USERS\", "")
        $userDirectories = Get-ChildItem 'C:\users' -Directory | Select-Object -ExpandProperty Name

        foreach ($i in $userDirectories) {
            $paths = @(
                "Registry::hklm\System\CurrentControlSet\Services\bam\State\UserSettings\$sid\Device\HarddiskVolume*\Users\$i\AppData\Local\OneLaunch\*\chromium\chromium.exe",
                "Registry::hklm\System\CurrentControlSet\Services\bam\State\UserSettings\$sid\Device\HarddiskVolume*\Users\$i\AppData\Local\OneLaunch\*\onelaunch.exe",
                "Registry::hklm\System\CurrentControlSet\Services\bam\State\UserSettings\$sid\Device\HarddiskVolume*\Users\$i\AppData\Local\Temp\*\onelaunch_*",
                "Registry::hklm\System\CurrentControlSet\Services\bam\State\UserSettings\$sid\Device\HarddiskVolume*\Users\$i\AppData\Local\OneLaunch\*\onelaunchtray.exe"
            )

            foreach ($path in $paths) {
                if (Test-Path -path $path) {
                    echo "+ $path"
                    Remove-Item -Path $path -ErrorAction SilentlyContinue
                }
            }
        }
    }
}



$paths = @(
    "Registry::hklm\Software\OneLaunch",
    "Registry::hklm\Software\Wow6432Node\Microsoft\Tracing\onelaunch_RASAPI32",
    "Registry::hklm\Software\Wow6432Node\Microsoft\Tracing\onelaunch_RASMANCS",
    "Registry::hklm\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchLaunchTask",
    "Registry::hklm\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchUpdateTask",
    "Registry::hklm\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\ChromiumLaunchTask"
)

foreach ($path in $paths) {
    if (Test-Path -path $path) {
        echo "+ $path"
        Remove-Item -path $path -recurse -ErrorAction SilentlyContinue
    }
}



echo '-----------------------------';

echo 'Running Checks:'

echo '-----------------------------'; 
#Check Removal

foreach ($user in $users) {
    if ($user -ne "Public") {
        $check1 = Test-Path "C:\Users\$user\AppData\Local\OneLaunch"
        if ($check1 -eq "True") {
            "This script failed to remove C:\Users\$user\AppData\Local\OneLaunch"
        }
        $check2 = Test-Path "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneLaunch"
        if ($check2 -eq "True") {
            "This script failed to remove C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneLaunch"
        } else { "Script ran successfully"}
    }
}

foreach ($sid in $sids) {
    if ($sid -notlike "*_Classes") {
        $check3 = Test-Path -path "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\{4947c51a-26a9-4ed0-9a7b-c21e5ae0e71a}_is1" -ErrorAction SilentlyContinue
        if ($check3 -eq "True") {
            "This script failed to remove Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\{4947c51a-26a9-4ed0-9a7b-c21e5ae0e71a}_is1"
        }
        else {
            continue
        }
    }
}

$check4 = Test-Path -path "Registry::hklm\Software\OneLaunch" -ErrorAction SilentlyContinue
if ($check4) {
    "This script failed to remove HKEY_LOCAL_MACHINE\Software\OneLaunch"
}
else {
    continue
}

$check5 = Test-Path -path "Registry::hklm\Software\Wow6432Node\Microsoft\Tracing\onelaunch_RASAPI32" -ErrorAction SilentlyContinue
if ($check5) {
    "This script failed to remove HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Tracing\onelaunch_RASAPI32"
}
else {
    continue
}

$check6 = Test-Path -path "Registry::hklm\Software\Wow6432Node\Microsoft\Tracing\onelaunch_RASMANCS" -ErrorAction SilentlyContinue
if ($check6) {
    "This script failed to remove HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Tracing\onelaunch_RASMANCS"
}
else {
    continue
}

$check7 = Test-path -path "Registry::hklm\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchLaunchTask" -ErrorAction SilentlyContinue
if ($check7) {
    "This script failed to remove HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchLaunchTask"
}
else{
    continue
}

$check8 = Test-path -path "Registry::hklm\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchUpdateTask" -ErrorAction SilentlyContinue
if ($check8) {
    "This script failed to remove HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\OneLaunchUpdateTask"
}
else{
    continue
}

$check9 = Test-path -path "Registry::hklm\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\ChromiumLaunchTask" -ErrorAction SilentlyContinue
if ($check9) {
    "This script failed to remove HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\ChromiumLaunchTask"
}
else{
    continue
}
