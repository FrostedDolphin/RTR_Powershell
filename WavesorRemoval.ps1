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


echo Killing Browsers
cmd /c taskkill.exe /F /IM wavebrowser.exe
#cmd /c taskkill.exe /F /IM chrome.exe
#cmd /c taskkill.exe /F /IM IEXPLORE.EXE
#cmd /c taskkill.exe /F /IM msedge.exe
#cmd /c taskkill.exe /F /IM firefox.exe

echo "Forcing Loggoff for locked files"
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

echo '------------------------';

echo 'Process(es) Terminated'

echo '------------------------';

if ($badprocs){

Foreach ($badproc in $badprocs){

echo $badproc

stop-process -Id $badproc -force

}

}

elseif ($SWUpdater){

Foreach ($SWUpdater in $SWUpdater){

echo $SWUpdater

stop-process -Id $SWUpdater -force

}

}

else {

echo 'No Processes Terminated.'

}

$stasks = schtasks /query /fo csv /v | convertfrom-csv | ?{$_.TaskName -like 'Wavesor*'} | select -exp TaskName

echo ''

echo '----------------------------';

' Scheduled Task(s) Removed:'

echo '----------------------------';

if ($stasks){

Foreach ($task in $stasks){

echo "$task"

schtasks /delete /tn $task /F

}

}

else {"No Scheduled Tasks Found."};

$badDirs = 'C:\Users\*\Wavesor Software',

'C:\Users\*\Downloads\Wave Browser*.exe',

'C:\Users\*\AppData\Local\WaveBrowser',

'C:\Windows\System32\Tasks\Wavesor Software_*',

'C:\WINDOWS\SYSTEM32\TASKS\WAVESORSWUPDATERTASKUSER*CORE',

'C:\WINDOWS\SYSTEM32\TASKS\WAVESORSWUPDATERTASKUSER*UA',

'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\WINDOWS\START MENU\PROGRAMS\WAVEBROWSER.LNK',

'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\WAVEBROWSER.LNK',

'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\USER PINNED\TASKBAR\WAVEBROWSER.LNK'

echo ''

echo '-------------------------------';

echo 'File System Artifacts Removed;'

echo '-------------------------------';

start-sleep -s 2;

ForEach ($badDir in $badDirs) {

$dsfolder = gi -Path $badDir -ea 0| select -exp fullname;

if ( $dsfolder) {

echo "$dsfolder"

rm $dsfolder -recurse -force -ea 0

}

else {

}

}

$checkhandle = gi -Path 'C:\Users\*\AppData\Local\WaveBrowser' -ea 0| select -exp fullname;

if ($checkhandle){

echo ""

echo "NOTE: C:\Users\*\AppData\Local\WaveBrowser' STILL EXISTS! A PROCESS HAS AN OPEN HANDLE TO IT!"

}

$badreg=

'Registry::HKU\*\Software\WaveBrowser',

'Registry::HKU\*\SOFTWARE\CLIENTS\STARTMENUINTERNET\WaveBrowser.*',

'Registry::HKU\*\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\wavebrowser.exe',

'Registry::HKU\*\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\WaveBrowser',

'Registry::HKU\*\Software\Wavesor',

'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\WavesorSWUpdaterTaskUser*UA',

'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\WavesorSWUpdaterTaskUser*Core',

'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\Wavesor Software_*'

echo ''

echo '---------------------------';

echo 'Registry Artifacts Removed:'

echo '---------------------------';

Foreach ($reg in $badreg){

$regoutput= gi -path $reg | select -exp Name

if ($regoutput){

"$regoutput `n"

reg delete $regoutput /f

}

else {}

}

$badreg2=

'Registry::HKU\*\Software\Microsoft\Windows\CurrentVersion\Run',

'Registry::HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'

echo ''

echo '----------------------------------';

echo 'Registry Run Persistence Removed:'

echo '----------------------------------';

Foreach ($reg2 in $badreg2){

$regoutput= gi -path $reg2 -ea silentlycontinue | ? {$_.Property -like 'Wavesor SWUpdater'} | select -exp Property ;

$regpath = gi -path $reg2 -ea silentlycontinue | ? {$_.Property -like 'Wavesor SWUpdater'} | select -exp Name ;

Foreach($prop in $regoutput){

If ($prop -like 'Wavesor SWUpdater'){

"$regpath value: $prop `n"

reg delete $regpath /v $prop /f

}

else {}

}

}
echo "ALL DONE"
