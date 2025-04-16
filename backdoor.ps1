# Rootkit / Backdoor Detection Script (Basic Check)
# Requires admin privileges

# 1. Check for hidden network connections
Write-Host "`n--- Active Network Connections ---" -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Format-Table -AutoSize

# 2. List listening ports and associated processes
Write-Host "`n--- Listening Ports and Associated Processes ---" -ForegroundColor Cyan
Get-NetTCPConnection -State Listen | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort    = $_.LocalPort
        ProcessName  = $proc.ProcessName
        PID          = $_.OwningProcess
    }
} | Sort-Object LocalPort | Format-Table -AutoSize

# 3. List auto-start entries (registry + startup folder)
Write-Host "`n--- Autorun Entries (Startup Items) ---" -ForegroundColor Cyan
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize

# 4. Suspicious scheduled tasks
Write-Host "`n--- Suspicious Scheduled Tasks ---" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | Format-Table TaskName, TaskPath, State -AutoSize

# 5. Services with unusual executable paths
Write-Host "`n--- Services with Executable Paths ---" -ForegroundColor Cyan
Get-WmiObject win32_service | Where-Object {
    $_.PathName -notlike "*Windows\System32*" -and $_.State -eq "Running"
} | Select-Object DisplayName, PathName, State | Format-Table -AutoSize

# 6. Unusual DLLs in system processes (requires SysInternals sigcheck.exe)
# Optional: Download sigcheck.exe and use this block
# Write-Host "`n--- Unsigned DLLs in Processes (Optional) ---" -ForegroundColor Cyan
# & ".\sigcheck.exe" -u -e -q

# 7. Compare hashes of critical system files (requires baseline hashes)
# Optional: For advanced use, compare hashes against clean image

# 8. Detect hidden files/folders in system directories
Write-Host "`n--- Hidden Files in System Directories ---" -ForegroundColor Cyan
$paths = @("C:\Windows", "C:\Windows\System32")
foreach ($path in $paths) {
    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match "Hidden" } |
    Select-Object FullName, Attributes
}

# 9. List processes without a company name (possible unsigned)
Write-Host "`n--- Processes Without Company Name ---" -ForegroundColor Cyan
Get-Process | ForEach-Object {
    try {
        $path = $_.Path
        $info = Get-ItemProperty $path
        $versionInfo = $info.VersionInfo
        if (!$versionInfo.CompanyName) {
            [PSCustomObject]@{
                ProcessName = $_.ProcessName
                PID         = $_.Id
                Path        = $path
            }
        }
    } catch {}
} | Format-Table -AutoSize

Write-Host "`nScan completed. Review above output for anomalies." -ForegroundColor Green
