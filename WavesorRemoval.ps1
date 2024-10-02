Function Set-Owner {
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.
        .DESCRIPTION
            Changes owner of a file or folder to another user or group.
        .PARAMETER Path
            The folder or file that will have the owner changed.
        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.
            Default value is 'Builtin\Administrators'
        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder.
        .NOTES
            Name: Set-Owner
            Author: Boe Prox
            Version History:
                 1.0 - Boe Prox
                    - Initial Version
        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt
            Description
            -----------
            Changes the owner of test.txt to Builtin\Administrators
        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt -Account 'Domain\bprox
            Description
            -----------
            Changes the owner of test.txt to Domain\bprox
        .EXAMPLE
            Set-Owner -Path C:\temp -Recurse 
            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators
        .EXAMPLE
            Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\bprox'
            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Domain\bprox
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path,
        [parameter()]
        [string]$Account = 'Builtin\Administrators',
        [parameter()]
        [switch]$Recurse
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;
             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }
    Process {
        ForEach ($Item in $Path) {
            Write-Verbose "FullName: $Item"
            #The ACL objects do not like being used more than once, so re-create them on the Process block
            $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
            $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $FileOwner = New-Object System.Security.AccessControl.FileSecurity
            $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $AdminACL = New-Object System.Security.AccessControl.FileSystemAccessRule('Builtin\Administrators','FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow')
            $FileAdminAcl.AddAccessRule($AdminACL)
            $DirAdminAcl.AddAccessRule($AdminACL)
            Try {
                $Item = Get-Item -LiteralPath $Item -Force -ErrorAction Stop
                If (-NOT $Item.PSIsContainer) {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
                        Try {
                            $Item.SetAccessControl($FileOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($FileAdminAcl)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
                        Try {
                            $Item.SetAccessControl($DirOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirAdminAcl) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        Get-ChildItem $Item -Force | Set-Owner @PSBoundParameters
                    }
                }
            } Catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }
    }
    End {  
        #Remove privileges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

Set-Variable -Name ErrorActionPreference -Value SilentlyContinue


#echo Killing Browsers
cmd /c taskkill.exe /F /IM wavebrowser.exe

#echo "Forcing Loggoff for locked files"
logoff 1
logoff 2
logoff 3
logoff 4
logoff 5
logoff 6
logoff 7
$ErrorActionPreference = 'SilentlyContinue'

$badprocs=get-process | ?{$_.name -like 'Wave*Browser*'} | select -exp Id;
$SWUpdater=get-process | ?{$_.name -like 'SWUpdater'} | select -exp Id;


Write-Output 'Removed:'


if ($badprocs){
    Foreach ($badproc in $badprocs){
        Write-Output "Proc: $badproc.Name"
        stop-process -Id $badproc.Id -force
    }
}

elseif ($SWUpdater){
    Foreach ($process in $SWUpdater){
        Write-Output "Proc: $process.Name"
        stop-process -Id $process.Id -force
    }
}


else {
    Write-Output 'No Processes.'
}

$stasks = schtasks /query /fo csv /v | convertfrom-csv | ?{$_.TaskName -like 'Wavesor*'} | select -exp TaskName

if ($stasks){
    Foreach ($task in $stasks){
        Write-Output "SchTask- $task"
        schtasks /delete /tn $task /F
    }
} else {
    Write-Output "No Scheduled Tasks."
}

$badDirs = 'C:\Users\*\Wavesor Software',
           'C:\Users\*\Downloads\Wave Browser*.exe',
           'C:\Users\*\AppData\Local\WaveBrowser',
           'C:\Windows\System32\Tasks\Wavesor Software_*',
           'C:\WINDOWS\SYSTEM32\TASKS\WAVESORSWUPDATERTASKUSER*CORE',
           'C:\WINDOWS\SYSTEM32\TASKS\WAVESORSWUPDATERTASKUSER*UA',
           'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\WINDOWS\START MENU\PROGRAMS\WAVEBROWSER.LNK',
           'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\WAVEBROWSER.LNK',
           'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\USER PINNED\TASKBAR\WAVEBROWSER.LNK', 
           'C:\USERS\*\DESKTOP\WAVEBROWSER.LNK',
           'C:\Users\*\AppData\Local\Temp\Wave'

start-sleep -s 2

$foundFiles = $false

ForEach ($badDir in $badDirs) {
    $dsfolder = gi -Path $badDir -ea 0 | select -exp fullname
    if ($dsfolder) {
        Write-Output "Dir- $dsfolder"
        rm $dsfolder -recurse -force -ea 0
        $foundFiles = $true
    }
}

if (-not $foundFiles) {
    Write-Output "No Files."
}

$checkhandle = gi -Path 'C:\Users\*\AppData\Local\WaveBrowser' -ea 0| select -exp fullname
if ($checkhandle){
    Write-Output "C:\Users\*\AppData\Local\WaveBrowser' EXISTS: OPEN HANDLE!"
}

$foundRegItems = $false

$HKUKeys = Get-ChildItem -Path Registry::HKU | Select-Object -ExpandProperty Name
$badreg = @(
    'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\WavesorSWUpdaterTaskUserUA',
    'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\WavesorSWUpdaterTaskUserCore',
    'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\Wavesor Software'
)

$badregHKU = @(
    'Software\WaveBrowser',
    'SOFTWARE\CLIENTS\STARTMENUINTERNET\WaveBrowser',
    'SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\wavebrowser.exe',
    'SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\WaveBrowser',
    'Software\Wavesor',
    'SOFTWARE\Wavesor',
    'WaveBrwsHTM',
    'WavesorSWUpdater',
    'OPENWITHPROGIDS|WAVEBRWSHTM'
)


foreach ($HKUKey in $HKUKeys) {
    foreach ($reg in $badregHKU) {
        $regPath = "Registry::$HKUKey\$reg"
        if (Test-Path $regPath) {
            $regoutput = Get-Item -Path $regPath | Select-Object -ExpandProperty Name
            if ($regoutput) {
                Write-Output "Regkey- $regoutput"
                reg delete $regoutput /f
                $foundRegItems = $true
            }
        }
    }
}

foreach ($reg in $badreg) {
    if (Test-Path $reg) {
        $regoutput = Get-Item -Path $reg | Select-Object -ExpandProperty Name
        if ($regoutput) {
            Write-Output"Regkeys- $regoutput"
            reg delete $regoutput /f
            $foundRegItems = $true
        }
    }
}

$badreg2 = @(
    'Software\Microsoft\Windows\CurrentVersion\Run',
    'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)


foreach ($HKUKey in $HKUKeys) {
    foreach ($reg in $badreg2) {
        $regPath = "Registry::$HKUKey\$reg"
        if (Test-Path $regPath) {
            $properties = Get-ItemProperty -Path $regPath
            foreach ($property in $properties.PSObject.Properties) {
                if ($property.Name -like 'Wavesor SWUpdater') {
                    Remove-ItemProperty -Path $regPath -Name $property.Name
                    Write-Output "Regkey- $property.Name from $regPath"
                    $foundRegItems = $true
                }
            }
        }
    }
}
if (-not $foundRegItems) {
    Write-Output "No reg items"
}
