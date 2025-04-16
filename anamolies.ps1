# Simple Function to color suspicious items
function Write-Flagged {
    param([string]$Text, [string]$Level)
    switch ($Level) {
        "High"   { Write-Host "[!] $Text" -ForegroundColor Red }
        "Medium" { Write-Host "[*] $Text" -ForegroundColor Yellow }
        default  { Write-Host "[+] $Text" -ForegroundColor Green }
    }
}

# 1. Suspicious Listening Ports
Write-Host "`n--- Suspicious Listening Ports ---" -ForegroundColor Cyan
$knownPorts = @(135, 139, 445, 3389, 80, 443, 22, 53, 1433, 22)  # Extend as needed
Get-NetTCPConnection -State Listen | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $port = $_.LocalPort
    $pname = $proc.ProcessName
    if ($knownPorts -notcontains $port -and $port -gt 1024) {
        Write-Flagged "$pname is listening on uncommon port $port (PID: $_.OwningProcess)" "Medium"
    }
}

# 2. Processes with no Company Name (possible unsigned or packed)
Write-Host "`n--- Processes Without Company Info ---" -ForegroundColor Cyan
Get-Process | ForEach-Object {
    try {
        $info = Get-ItemProperty $_.Path
        $company = $info.VersionInfo.CompanyName
        if ([string]::IsNullOrEmpty($company)) {
            Write-Flagged "$($_.ProcessName) (PID: $($_.Id)) has no company info" "Medium"
        }
    } catch {}
}

# 3. Suspicious Auto-run Entries
Write-Host "`n--- Auto-start Entries in Suspicious Locations ---" -ForegroundColor Cyan
Get-CimInstance -ClassName Win32_StartupCommand | ForEach-Object {
    if ($_.Command -notmatch "Windows\\System32|Program Files") {
        Write-Flagged "Autorun: $($_.Name) from $($_.Command)" "Medium"
    }
}

# 4. Services Outside System Folders
Write-Host "`n--- Services Running from Non-System Paths ---" -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object { $_.State -eq "Running" } | ForEach-Object {
    if ($_.PathName -notmatch "System32|SysWOW64|Program Files") {
        Write-Flagged "Service '$($_.DisplayName)' running from '$($_.PathName)'" "Medium"
    }
}

# 5. Non-Microsoft Scheduled Tasks
Write-Host "`n--- Non-Microsoft Scheduled Tasks ---" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | ForEach-Object {
    Write-Flagged "Scheduled Task: $($_.TaskName) in $($_.TaskPath)" "Medium"
}
