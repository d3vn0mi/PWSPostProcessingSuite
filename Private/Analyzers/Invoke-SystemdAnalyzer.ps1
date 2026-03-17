function Invoke-SystemdAnalyzer {
    <#
    .SYNOPSIS
        Analyzes systemd service and timer files for persistence and suspicious configurations.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect service files from multiple locations
    $servicePaths = @(
        '/etc/systemd/system'
        '/usr/lib/systemd/system'
        '/lib/systemd/system'
        '/run/systemd/system'
        '/home'  # user-level services
    )

    $suspiciousPaths = @('/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/')
    $allServiceFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    foreach ($svcPath in $servicePaths) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $svcPath -Filter '*.service' -Recurse
        foreach ($f in $files) { $allServiceFiles.Add($f) }
        $timers = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $svcPath -Filter '*.timer' -Recurse
        foreach ($f in $timers) { $allServiceFiles.Add($f) }
    }

    if ($allServiceFiles.Count -eq 0) {
        return @()
    }

    foreach ($svcFile in $allServiceFiles) {
        $lines = Read-ArtifactContent -Path $svcFile.FullName
        $content = $lines -join "`n"
        $fileName = $svcFile.Name

        # Extract ExecStart, ExecStartPre, ExecStartPost, ExecStop values
        $execLines = $lines | Where-Object { $_ -match '^\s*Exec(Start|Stop|Reload)(Pre|Post)?\s*=' }

        foreach ($execLine in $execLines) {
            $execValue = ($execLine -split '=', 2)[1].Trim().TrimStart('-').TrimStart('!')

            # Check for execution from suspicious paths
            foreach ($suspPath in $suspiciousPaths) {
                if ($execValue -match [regex]::Escape($suspPath)) {
                    $findings.Add((New-Finding -Id "SYSD-001" -Severity "Critical" -Category "Persistence" `
                        -Title "Systemd service executes from suspicious path: $fileName" `
                        -Description "Service $fileName executes a binary from $suspPath which is a world-writable temporary directory. This is a strong indicator of persistence by a malicious actor." `
                        -ArtifactPath $svcFile.FullName `
                        -Evidence @($execLine.Trim()) `
                        -Recommendation "Investigate the binary and the service. Legitimate services should not run from /tmp or /dev/shm." `
                        -MITRE "T1543.002"))
                    break
                }
            }

            # Check for download-and-execute patterns
            if ($execValue -match '(wget|curl).*\|\s*(bash|sh)' -or $execValue -match 'base64\s+-d') {
                $findings.Add((New-Finding -Id "SYSD-002" -Severity "Critical" -Category "Persistence" `
                    -Title "Systemd service contains download-execute or encoded command: $fileName" `
                    -Description "Service $fileName contains patterns indicating download-and-execute or encoded command execution." `
                    -ArtifactPath $svcFile.FullName `
                    -Evidence @($execLine.Trim()) `
                    -Recommendation "Immediately investigate this service - likely malicious persistence." `
                    -MITRE "T1543.002"))
            }

            # Check for reverse shell patterns
            if ($execValue -match '/dev/tcp/' -or $execValue -match 'nc\s+.*-e' -or $execValue -match 'mkfifo.*nc') {
                $findings.Add((New-Finding -Id "SYSD-003" -Severity "Critical" -Category "Persistence" `
                    -Title "Systemd service contains reverse shell: $fileName" `
                    -Description "Service $fileName contains a reverse shell pattern, indicating active compromise." `
                    -ArtifactPath $svcFile.FullName `
                    -Evidence @($execLine.Trim()) `
                    -Recommendation "This is very likely a backdoor. Investigate immediately and check for lateral movement." `
                    -MITRE "T1543.002"))
            }
        }

        # Check for Type=oneshot with RemainAfterExit (common in persistence)
        if ($content -match 'Type\s*=\s*oneshot' -and $content -match 'RemainAfterExit\s*=\s*yes') {
            # Only flag if combined with suspicious exec
            $hasSupiciousExec = $false
            foreach ($execLine in $execLines) {
                $val = ($execLine -split '=', 2)[1].Trim()
                if ($val -match '/tmp/|/dev/shm/|base64|curl|wget') {
                    $hasSupiciousExec = $true
                    break
                }
            }
            if ($hasSupiciousExec) {
                $findings.Add((New-Finding -Id "SYSD-004" -Severity "High" -Category "Persistence" `
                    -Title "Suspicious oneshot service with RemainAfterExit: $fileName" `
                    -Description "Service $fileName is a oneshot service that remains after exit, combined with suspicious execution commands." `
                    -ArtifactPath $svcFile.FullName `
                    -Evidence @("Type=oneshot, RemainAfterExit=yes") `
                    -Recommendation "Review the purpose of this service and its execution commands." `
                    -MITRE "T1543.002"))
            }
        }

        # Check for services wanting to run before/after multi-user.target (early boot persistence)
        if ($content -match 'WantedBy\s*=\s*multi-user\.target' -or $content -match 'WantedBy\s*=\s*default\.target') {
            # Check if it's in a non-standard location
            $relativePath = $svcFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
            if ($relativePath -match 'home|tmp|run/user') {
                $findings.Add((New-Finding -Id "SYSD-005" -Severity "High" -Category "Persistence" `
                    -Title "User-level service targets multi-user.target: $fileName" `
                    -Description "A service file in a non-standard location is configured to start at boot." `
                    -ArtifactPath $svcFile.FullName `
                    -Evidence @("Location: $relativePath") `
                    -Recommendation "Verify this is a legitimate user service and not unauthorized persistence." `
                    -MITRE "T1543.002"))
            }
        }
    }

    # Informational summary
    $serviceCount = @($allServiceFiles | Where-Object { $_.Name -like '*.service' }).Count
    $timerCount = @($allServiceFiles | Where-Object { $_.Name -like '*.timer' }).Count
    $findings.Add((New-Finding -Id "SYSD-INFO" -Severity "Informational" -Category "Persistence" `
        -Title "Systemd configuration summary" `
        -Description "Found $serviceCount service files and $timerCount timer files." `
        -ArtifactPath "/etc/systemd/" `
        -Evidence @($allServiceFiles | ForEach-Object { $_.Name }) `
        -Recommendation "Review all custom services for legitimacy"))

    return $findings.ToArray()
}
