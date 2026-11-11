# Automated Log Analysis Tool

PowerShell and Python tool that analyses security logs and generates a timestamped investigation report.

**Context:** Individual project – Advanced Scripting for Cyber Security, TU Dublin (April 2026)

**Tools:** Python, PowerShell, Regex

## What it does
`run.ps1` runs three detection scripts and combines their output into one report:
- **detect_auth.py** – SSH brute-force detection in `auth.log` (HIGH ≥ 5 attempts, MEDIUM 3–4)
- **detect_ioc.py** – matches `access.log` against known malicious IPs and paths in `ioc.txt`
- **detect_powershell.ps1** – flags encoded commands, reconnaissance, malicious downloads and exfiltration

## Results
- **105 suspicious IPs** detected (50 HIGH / 55 MEDIUM)
- **8 IOC matches** (6 HIGH)
- **8 suspicious PowerShell events**, covering the full attack chain from encoded command to exfiltration

Sample output: [`investigation_report_2026-05-02_00-49.txt`](investigation_report_2026-05-02_00-49.txt)

## How to run
Requires PowerShell and Python 3 (no extra packages).
```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

## My contribution
I designed and wrote all the scripts and the report generation.

*Sample logs were provided for coursework. No sensitive data is included.*
