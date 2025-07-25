#desc: Removes Brave Browser on Windows
function StopProcesses {
    param (
        [string]$processName
        )
    $brave_processes = Get-Process | Where-Object {$_.ProcessName -like $processName} 
    if ($brave_processes) {
	    $brave_pids = $brave_processes.Id
	    $brave_pids | ForEach-Object { 
		Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
      } 
   } 
}

$packageName = "*brave*"
$regpath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\BraveSoftware Brave-Browser"
$braveProgFilesPath = "C:\Program Files (x86)\BraveSoftware\"

Write-Output "[+] Killing any active Brave app related processes...`n"
$pid_result = StopProcesses -processName $packageName
Start-Sleep -Seconds 5

Write-Output "[+] Looking for Brave Browser...`n"
if (Test-Path $regpath) {
	Write-Output "[+] Brave Browser found. Proceding with uninstall`n"
	$uninstall_string = Get-ItemPropertyValue -Path $regpath -Name 'UninstallString'
	$filepath_args = $uninstall_string -replace '^"' -split '"'
    $command = $filepath_args[0]
    $args = $filepath_args[1]
	Start-Process -FilePath $command -ArgumentList $args -NoNewWindow
	Write-Output "[+] Ran $command with args $args"
	Write-Output "[+] Waiting for the process to finish...sleeping for 30 sec`n"
	Start-Sleep -Seconds 30

	if (-not (Test-Path $regpath)) {
		Write-Output "[+] Brave app was successful uninstalled"
	} else {
		Write-Output "[-] Failed to uninstall Brave app"
        $pid_result = StopProcesses -processName $packageName
        Write-Output "[+] Killed hung uninstall process"
		} 
} else {
    Write-Output "[-] Brave Browser was not found in registry`n"
}

Write-Output "[+] Checking different artifact paths`n"
if (Test-Path $braveProgFilesPath){
    try {
        Remove-Item -Path $braveProgFilesPath -Recurse -Force
        Write-Output "[+] Removed files from $braveProgFilesPath"
    } catch {
        Write-Output "[-] Error: $_"
    }
} else {
    Write-Output "[-] Path '$braveProgFilesPath' doesn't exist`n"
}


$users = Get-ChildItem -Path "C:\users" | Select-Object name -ExpandProperty name | Select-String -Pattern "\b[a-zA-Z]{2,3}\d+\b"
foreach ($user in $users){
    $braveAppDataPath = "C:\Users\$user\AppData\Local\BraveSoftware\"
    Write-Output "[+] Checking path $braveAppDataPath"

    if (Test-Path $braveAppDataPath){
        try {
            Remove-Item -Path $braveAppDataPath -Recurse -Force
            Write-Output "[+] Removed files from $braveAppDataPath`n"
        } catch {
            Write-Output "[-] Error: $_"
        }
    } else {
        Write-Output "[-] Path '$braveAppDataPath' doesn't exist`n"
    }

}
