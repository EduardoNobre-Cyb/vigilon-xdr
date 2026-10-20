$ErrorActionPreference = "Stop"
$TaskName = "Vigilon EDR Sensor"

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*run-agent.ps1*" -or $_.CommandLine -like "*windows_agent.py*" } | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Remove-Item -Recurse -Force "C:\Program Files\Vigilon EDR" -ErrorAction SilentlyContinue
Write-Host "Vigilon EDR Sensor removed. Settings and logs kept in C:\ProgramData\Vigilon EDR"
Write-Host "To remove Sysmon: C:\Sysmon\Sysmon64.exe -u"