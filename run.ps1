# Getting the directory of my current script
$myscriptdirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

# Building the path to rapport.txt with timestamp
$mydate = Get-Date -Format "yyyy-MM-dd_HH-mm"
$MyReport = Join-Path $myscriptdirectory "investigation_report_$mydate.txt"

# Path to the detect_auth.py script
$authScript = Join-Path $myscriptdirectory "scripts\detect_auth.py"

# Path to the detetct_ioc.py script
$iocScript = Join-Path $myscriptdirectory "scripts\detect_ioc.py"

# Path to the detect_powershell.ps1 script
$pshellScript = Join-Path $myscriptdirectory "scripts\detect_powershell.ps1"



# Clear old report if the file investigation_report.txt esixts or create it if it does not exist
"" | Set-Content $MyReport -Encoding utf8

"***** AUTH LOG ANALYSIS *****" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8
python "$authScript" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8

"***** IOC ANALYSIS *****" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8
python "$iocScript" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8

"***** POWERSHELL ANALYSIS *****" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8
powershell -ExecutionPolicy Bypass -File "$pshellScript" | Out-File $MyReport -Append -Encoding utf8
"" | Out-File $MyReport -Append -Encoding utf8



