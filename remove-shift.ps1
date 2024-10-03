#Desc: This is a script that is aimed to automate the Shift removal commands seen in shift summary. Shift browser is being treated as adware due to the way it's delivered to users.

Set-Variable -Name ErrorActionPreference -Value SilentlyContinue

# Kill shift if it is running.
Get-Process -Name "shift" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Forensic locations of Shift
$badDirs = 'C:\Users\*\AppData\Local\Shift\',
           'C:\Users\*\Downloads\Shift - *.exe',
           'C:\Users\*\Downloads\shift - *.exe',
           'C:\Users\*\Downloads\Shift-*.exe',
           'C:\Users\*\Downloads\shift-*.exe',
           'C:\Users\*\Downloads\Shift Setup*.exe',
           'C:\Users\*\Downloads\shift setup*.exe',,  
           'C:\Users\*\OneDrive - MassMutual\Downloads\Shift - *.exe',
           'C:\Users\*\OneDrive - MassMutual\Downloads\shift - *.exe',
           'C:\Users\*\OneDrive - MassMutual\Downloads\Shift-*.exe',
           'C:\Users\*\OneDrive - MassMutual\Downloads\shift-*.exe',
           'C:\Users\*\OneDrive - MassMutual\Downloads\Shift Setup*.exe',
           'C:\Users\*\OneDrive - MassMutual\Downloads\shift setup*.exe',
           'C:\Users\*\AppData\Local\ShiftData',
           'C:\WINDOWS\SYSTEM32\TASKS\ShiftLaunchTask',
           'C:\USERS\*\DESKTOP\Shift.LNK',
           'C:\Program Files (x86)\Shift',
           'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Shift.lnk',
           'C:\Microsoft\Windows\Start Menu\Programs\Startup\Shift Browser.lnk',
           'C:\Users\*\Desktop\Shift Browser.lnk'

$foundFiles = $false

ForEach ($badDir in $badDirs) {
    $dsfolder = gi -Path $badDir -ea 0 | select -exp fullname
    if ($dsfolder) {
        Write-Output "+ $dsfolder"
        Remove-Item $dsfolder -Force -Recurse
        $foundFiles = $true
    }
}    
if (-not $foundFiles) {
    Write-Output "No files"
}




# Variable to hold scheduled tasks associated with Shift Browser
$stasks = schtasks /query /fo csv /v | convertfrom-csv | ?{$_.TaskName -like 'ShiftLaunchTask'} | select -exp TaskName

# Loop iterates thru scheduled tasks, removing anything that matches what we found above. 
if ($stasks){
    Foreach ($task in $stasks){
        Write-Output "SchTask - $task"
        schtasks /delete /tn $task /F
    }
} else {
    Write-Output "No SchTask"
}

$HKUKeys = Get-ChildItem -Path Registry::HKU | Select-Object -ExpandProperty Name

$badregHKU = @(
    'Software\Shift',
    'Software\ShiftData',
    'SOFTWARE\CLIENTS\STARTMENUINTERNET\Shift',
    'SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\Shift'
)

$foundRegItems = $false

foreach ($HKUKey in $HKUKeys) {
    foreach ($reg in $badregHKU) {
        $regPath = "Registry::$HKUKey\$reg"
        if (Test-Path $regPath) {
            $regoutput = Get-Item -Path $regPath | Select-Object -ExpandProperty Name
            if ($regoutput) {
                write-output "regkey- $regoutput"
                reg delete $regoutput /f > $null 2>&1
                $foundRegItems = $true
            }
        }
    }
}

if (-not $foundRegItems) {
    Write-Output "No reg items"
}
