#Desc: This script will kill the ZoomInfo process "coordinator.exe," collect a list of user accounts, loop through each path, delete ZoomInfo, and tell the operator if the removal failed or was successful.

# Get the ZoomInfo process if it's running and stop it
$zoomInfoProcess = Get-Process coordinator -ErrorAction SilentlyContinue
if ($zoomInfoProcess) {
    Write-Output "Stopping ZoomInfo process..."
    Stop-Process -Name coordinator -Force
    Write-Output "ZoomInfo process stopped successfully."
} else {
    Write-Output "ZoomInfo process is not running."
}

### Checking for user accounts
$users = Get-ChildItem C:\users | Select-Object name -ExpandProperty name
$test = @()

### Deleting OneLaunch directories
foreach ($user in $users) {
    if ($user -ne "Public") {
        $result = Test-Path -path "C:\Users\$user\AppData\Local\ZoomInfoCEUtility\"
        if ($result -eq "True") {
            $test += $user
        } else {
            continue
        }
        rm "C:\Users\$user\AppData\Local\ZoomInfoCEUtility\" -Force -Recurse -ErrorAction SilentlyContinue
    }
}


#Check Removal
foreach ($user in $users) {
    if ($user -ne "Public") {
        $check1 = Test-Path "C:\Users\$user\AppData\Local\ZoomInfoCEUtility\"
        if ($check1 -eq "True") {
            "This script failed to remove C:\Users\$user\AppData\Local\ZoomInfoCEUtility\"
        }else { "Script ran successfully"}
    }
}
