# Getting the directory of my current script
$myscriptdirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

# Building the path to powershell_log.txt
$MylogPath = Join-Path $myscriptdirectory "..\powershell_log.txt"

Write-Output ""
Write-Output "*** Suspicious PowerShell Activity Detection ***"

# Read the log file
$filecontent = Get-Content $MylogPath
$suspiciousActivityCount = 0
$suspiciousSecureDownload = 0
$totalHigh = 0
$totalMedium = 0

foreach ($l in $filecontent) {
   if ($l -like "*EncodedCommand*" -or $l -like "*ExecutionPolicy Bypass*" -or $l -like "*NoProfile*") {
        Write-Output "Suspicious Start: $l - Severity: HIGH"
		$suspiciousActivityCount = $suspiciousActivityCount + 1
		$totalHigh = $totalHigh + 1
    }
	
   elseif ($l -like "*whoami*" -or $l -like "*ipconfig*" -or $l -like "*net user*") {
        Write-Output "Reconnaissance: $l - Severity: MEDIUM"
		$suspiciousActivityCount = $suspiciousActivityCount + 1
		$totalMedium = $totalMedium +1
    }
	
   elseif ($l -like "*Invoke-WebRequest*") {
	   
	    if ($l -like "*-Upload data.zip*") {
			Write-Output "Exfiltration: $l - Severity: HIGH"
		    $suspiciousActivityCount = $suspiciousActivityCount + 1
			$totalHigh = $totalHigh + 1
		}
	   
        elseif ($l -like "*http://*") {
			if ($l -match "\.exe|\.zip|\.ps1|\.bat|\.dll" -or $l -like "*payload*" -or $l -like "*malware*" -or $l -like "*backdoor*" -or $l -like "*shell*" -or $l -like "*exploit*") {
			Write-Output "Malicious download: $l - Severity: HIGH"
			$suspiciousActivityCount = $suspiciousActivityCount + 1
			$totalHigh = $totalHigh + 1
			
			}
			else {
			Write-Output "Suspicious download: $l - Severity: MEDIUM"
			$suspiciousActivityCount = $suspiciousActivityCount + 1
			$totalMedium = $totalMedium +1
			}
		}
		
		elseif ($l -like "*https://*") {
			if ($l -match "\.exe|\.zip|\.ps1|\.bat|\.dll" -or $l -like "*payload*" -or $l -like "*malware*" -or $l -like "*backdoor*" -or $l -like "*shell*" -or $l -like "*exploit*") {
			Write-Output "Suspicious secure download: $l - Severity: MEDIUM"
			$suspiciousActivityCount = $suspiciousActivityCount + 1
			$suspiciousSecureDownload = $suspiciousSecureDownload + 1
			$totalMedium = $totalMedium +1
			
			}
		}
		
    }
	
   elseif ($l -like "*Compress-Archive*" -and $l -like "*C:\Users\student\Documents\data.zip*") {
        Write-Output "Collection: $l - Severity: MEDIUM"
		$suspiciousActivityCount = $suspiciousActivityCount + 1
		$totalMedium = $totalMedium +1
    }


}
Write-Output ""
Write-Output "Total Number of Suspicious PowerShell or Malicious Logs: $suspiciousActivityCount"
Write-Output "Total Number of Suspicious Secure Downloads: $suspiciousSecureDownload"
Write-Output "Total Number of High Alerts: $totalHigh"
Write-Output "Total Number of Medium Alerts: $totalMedium"