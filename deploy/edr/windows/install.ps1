param(
    [string]$SourceDir = (Resolve-Path "$PSScriptRoot\..\..\..").Path,
    [string]$BackendUrl = "http://192.168.56.1:5000",
    [string]$Python = "",
    [string]$SysmonDir = "C:\Sysmon"
)
$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\Vigilon EDR"
$DataDir = "C:\ProgramData\Vigilon EDR"
$LogDir = "$DataDir\logs"
$EnvFile = "$DataDir\agent.env"
$TaskName = "Vigilon EDR Sensor"
$ModelSource = "$SourceDir\data\models\EDR\windows"

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an Administrator PowerShell session."
}
if (-not (Test-Path "$SourceDir\agents\endpoint_agent\windows_agent.py")) {
    throw "Can't find the Windows agent in $SourceDir\agents\endpoint_agent."
}
if (-not (Test-Path "$ModelSource\process_model.pkl")) {
    throw "Can't find the Windows models in $SourceDir\data\models\EDR\windows. Train them first"
}
if (-not $Python) {
    $Python = (Get-Command python -ErrorAction Stop).Source
}
if ($Python -like "*\WindowsApps\*") {
    throw "$Python is the Microsoft Store shortcut, which SYSTEM can't run. Install Python from python.org, or pass -Python C:\path\to\python.exe"
}
Write-Host "Using Python: $Python"

$sysmon = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sysmon) {
    Write-Host "Sysmon is already installed ($($sysmon.Name))."
    if ($sysmon.Status -ne "Running") { Start-Service -Name $sysmon.Name }
} else {
    New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
    $sysmonExe = "$SysmonDir\Sysmon64.exe"
    $sysmonConfig = "$SysmonDir\sysmonconfig.xml"
    try {
        if (-not (Test-Path $sysmonExe)) {
            Write-Host "Downloading Sysmon from Microsoft..."
            Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$SysmonDir\Sysmon.zip" -UseBasicParsing
            Expand-archive -Path "$SysmonDir\Sysmon.zip" -DestinationPath $SysmonDir -Force
        }
        if (-not (Test-Path $sysmonConfig)) {
            Write-Host "Downloading the Sysmon config..."
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $sysmonConfig -UseBasicParsing
        }
    } catch {
        throw "Sysmon isn't installed and couldn't be downloaded. Copy $sysmonExe and $sysmonConfig to $SysmonDir and run this again. Details: $_"
    }
    & $sysmonExe -accepteula -i $sysmonConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed with code $LASTEXITCODE" }
    Write-Host "Sysmon installed."
}

$ErrorActionPreference = "Continue"
& $Python -c "import psutil, socketio, joblib, sklearn, numpy, pandas, win32evtlog" 2>&1 | Out-Null
$importsOk = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = "Stop"
if (-not $importsOk) {
    throw "Some agent packages are missing. From an Administrator prompt run `"$Python`" -m pip install -r `"$SourceDir\requirements-windows.txt`" (no --user)"
}

New-Item -ItemType Directory -Force -Path $InstallDir, $LogDir | Out-Null
robocopy "$SourceDir\agents" "$InstallDir\agents" /MIR /XD __pycache__ /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy (agents) failed with code $LASTEXITCODE" }
robocopy $ModelSource "$InstallDir\data\models\EDR\windows" /MIR /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy (models) failed with code $LASTEXITCODE" }

if (-not (Test-Path $EnvFile)) {
    $settings = @"

# Vigilon EDR sensor settings. After editing, run install.ps1 again
BACKEND_URL=$BackendUrl
PROCESS_COLLECTOR=sysmon
EDR_MODEL_DIR=$InstallDir\data\models\EDR\windows
AUTO_RESPONSE_MODE=dry_run
"@
    Set-Content -Path $EnvFile -Value $settings -Encoding ASCII
    Write-Host "Created $EnvFile"
} else {
    Write-Host "Keeping your existing $EnvFile"
}

$launcher = @"
# Written by install.ps1. Settings live in $EnvFile
`$ErrorActionPreference = "Continue"
Get-Content "$EnvFile" | Where-Object { `$_ -match '^\s*[^#\s][^=]*=' } | ForEach-Object {
    `$name, `$value = `$_ -split '=', 2
    [Environment]::SetEnvironmentVariable(`$name.Trim(), `$value.Trim(), "Process")
}
`$env:PYTHONPATH = "$installDir;$InstallDir\agents"
`$env:PYTHONUNBUFFERED = "1"
Set-Location "$InstallDir"
while (`$true) {
    # Keep one old log so agent.log can't fill the disk
    if ((Test-Path "$LogDir\agent.log") -and ((Get-Item "$LogDir\agent.log").Length -gt 10MB)) {
        Move-Item -Force "$LogDir\agent.log" "$LogDir\agent.log.1"
    }
    Add-Content -Path "$LogDir\agent.log" -Value "`$(Get-Date -Format s) launcher: starting agent"
    & "$Python" "$InstallDir\agents\endpoint_agent\windows_agent.py" *>> "$LogDir\agent.log"
    Add-Content -Path "$LogDir\agent.log" -Value "`$(Get-Date -Format s) launcher: agent exited (code `$LASTEXITCODE), restarting in 10s"
    Start-Sleep -Seconds 10
}
"@
Set-Content -Path "$InstallDir\run-agent.ps1" -Value $launcher -Encoding utf8

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\run-agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings -Force | Out-Null

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*run-agent.ps1*" -or $_.CommandLine -like "*windows_agent.py*" } | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 8
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table
Write-Host "Installed. Log: $LogDir\agent.log"
Write-Host "Follow it with: Get-Content '$LogDir\agent.log' -Wait -Tail 20"