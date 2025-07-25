#Desc: Compresses IIS logs for all configured sites and drops to a file share
Import-Module WebAdministration
Add-Type -Assembly System.IO.Compression.FileSystem

$Computer = $env:COMPUTERNAME
$Computer = $Computer.Replace('"', '')
$dropoff_path = "\\known\Good\Dropoff\Path\"

foreach($WebSite in $(get-website)) {
    $logFile="$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
    Write-OutPut "IIS Log Path for $($WebSite.name) : [$logfile]"
	$webname = $Website.name.Replace(' ', '')
	$output_filename = "$($dropoff_path)$($Computer)_$($webname).zip"
    write-output $output_filename
	[System.IO.Compression.ZipFile]::CreateFromDirectory($logfile, $output_filename);
} 
