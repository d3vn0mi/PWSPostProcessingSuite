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
                        -MITRE "T1543.002" `
                        -CVSSv3Score '9.4' `
                        -TechnicalImpact 'Allows attacker to maintain persistent access by executing malicious binaries from world-writable directories on every system boot.'))
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
                    -MITRE "T1543.002" `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'Enables remote code execution as root on every boot by downloading and executing attacker-controlled payloads via systemd service.'))
            }

            # Check for reverse shell patterns
            if ($execValue -match '/dev/tcp/' -or $execValue -match 'nc\s+.*-e' -or $execValue -match 'mkfifo.*nc') {
                $findings.Add((New-Finding -Id "SYSD-003" -Severity "Critical" -Category "Persistence" `
                    -Title "Systemd service contains reverse shell: $fileName" `
                    -Description "Service $fileName contains a reverse shell pattern, indicating active compromise." `
                    -ArtifactPath $svcFile.FullName `
                    -Evidence @($execLine.Trim()) `
                    -Recommendation "This is very likely a backdoor. Investigate immediately and check for lateral movement." `
                    -MITRE "T1543.002" `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'Active backdoor providing persistent remote shell access to the system on every boot, enabling full attacker control.'))
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
                    -MITRE "T1543.002" `
                    -CVSSv3Score '7.8' `
                    -TechnicalImpact 'May allow attacker to execute malicious commands at boot with persistence, using oneshot service pattern to avoid detection.'))
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
                    -MITRE "T1543.002" `
                    -CVSSv3Score '7.5' `
                    -TechnicalImpact 'May allow attacker to maintain persistent access across reboots via a service file in a non-standard location targeting boot.'))
            }
        }
    }

    # ----------------------------------------------------------------
    # SYSD-006: Writable systemd service/timer files
    # ----------------------------------------------------------------
    foreach ($svcFile in $allServiceFiles) {
        $relativePath = $svcFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
        # Check if the file's directory indicates it's a user-writable location
        if ($relativePath -match '^etc/systemd/system/' -or $relativePath -match '^usr/lib/systemd/') {
            # We can check file permissions if a file listing artifact exists
            # For now, flag files in /etc/systemd that are in home or tmp-sourced overrides
        }
    }

    # ----------------------------------------------------------------
    # SYSD-007: Systemd PATH contains writable directories
    # ----------------------------------------------------------------
    foreach ($svcFile in $allServiceFiles) {
        $lines = Read-ArtifactContent -Path $svcFile.FullName
        $content = $lines -join "`n"
        $fileName = $svcFile.Name

        foreach ($line in $lines) {
            if ($line -match '^\s*Environment\s*=.*PATH\s*=' -or $line -match '^\s*ExecSearchPath\s*=') {
                $pathValue = ''
                if ($line -match 'PATH\s*=\s*(.+?)(\s|$|")') {
                    $pathValue = $Matches[1]
                }
                elseif ($line -match 'ExecSearchPath\s*=\s*(.+)$') {
                    $pathValue = $Matches[1]
                }

                if ($pathValue) {
                    $pathDirs = $pathValue -split ':'
                    $writableDirs = $pathDirs | Where-Object { $_ -match '^(/tmp|/var/tmp|/dev/shm|/home|/run/user)' }
                    if ($writableDirs.Count -gt 0) {
                        $findings.Add((New-Finding -Id "SYSD-007" -Severity "High" -Category "Persistence" `
                            -Title "Systemd service PATH contains writable directory: $fileName" `
                            -Description "Service '$fileName' has writable directories in its PATH/ExecSearchPath: $($writableDirs -join ', '). This allows binary hijacking." `
                            -ArtifactPath $svcFile.FullName `
                            -Evidence @($line.Trim(), "Writable dirs: $($writableDirs -join ', ')") `
                            -Recommendation "Remove writable directories from the service PATH. Use absolute paths in ExecStart." `
                            -MITRE "T1574.007" `
                            -CVSSv3Score '7.8' `
                            -TechnicalImpact 'Writable directories in systemd service PATH allow any local user to place a malicious binary that will be executed with the service privileges.'))
                    }
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # SYSD-008: Services without security hardening
    # ----------------------------------------------------------------
    $hardeningDirectives = @('PrivateTmp', 'NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'ReadOnlyPaths')
    foreach ($svcFile in $allServiceFiles) {
        if ($svcFile.Name -notlike '*.service') { continue }
        $content = (Read-ArtifactContent -Path $svcFile.FullName) -join "`n"
        $fileName = $svcFile.Name

        # Only check services that run as root (no User= directive)
        if ($content -match 'User\s*=' -and $content -notmatch 'User\s*=\s*root') { continue }
        # Skip standard system services
        if ($fileName -match '^(systemd-|dbus|NetworkManager|sshd|rsyslog|cron)') { continue }

        # Check if the service is in /etc/systemd (custom services)
        $relativePath = $svcFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
        if ($relativePath -notmatch '^etc/systemd/') { continue }

        $missingHardening = @()
        foreach ($directive in $hardeningDirectives) {
            if ($content -notmatch "$directive\s*=") {
                $missingHardening += $directive
            }
        }

        if ($missingHardening.Count -ge 3) {
            $findings.Add((New-Finding -Id "SYSD-008" -Severity "Medium" -Category "Persistence" `
                -Title "Service without security hardening: $fileName" `
                -Description "Custom service '$fileName' running as root is missing $($missingHardening.Count) security hardening directives." `
                -ArtifactPath $svcFile.FullName `
                -Evidence @("Service: $fileName", "Missing: $($missingHardening -join ', ')") `
                -Recommendation "Add security hardening directives: PrivateTmp=true, NoNewPrivileges=true, ProtectSystem=strict, ProtectHome=true" `
                -MITRE "T1543.002" `
                -CVSSv3Score '5.3' `
                -TechnicalImpact 'Services without security hardening run with full root privileges and unrestricted filesystem access, increasing the impact of any service vulnerability.'))
        }
    }

    # ----------------------------------------------------------------
    # SYSD-009: Systemd timers executing from writable paths
    # ----------------------------------------------------------------
    foreach ($svcFile in $allServiceFiles) {
        if ($svcFile.Name -notlike '*.timer') { continue }
        $lines = Read-ArtifactContent -Path $svcFile.FullName
        $content = $lines -join "`n"

        # Find the associated service unit
        $unitName = ''
        if ($content -match 'Unit\s*=\s*(.+\.service)') {
            $unitName = $Matches[1]
        }
        else {
            $unitName = $svcFile.Name -replace '\.timer$', '.service'
        }

        # Look for the associated service and check its ExecStart
        $assocService = $allServiceFiles | Where-Object { $_.Name -eq $unitName }
        if ($assocService) {
            $svcContent = (Read-ArtifactContent -Path $assocService.FullName) -join "`n"
            if ($svcContent -match 'ExecStart\s*=\s*.*(/tmp/|/dev/shm/|/var/tmp/|/home/)') {
                $findings.Add((New-Finding -Id "SYSD-009" -Severity "High" -Category "Persistence" `
                    -Title "Timer-activated service executes from writable path: $($svcFile.Name)" `
                    -Description "Timer '$($svcFile.Name)' triggers service '$unitName' which executes from a user-writable directory." `
                    -ArtifactPath $svcFile.FullName `
                    -Evidence @("Timer: $($svcFile.Name)", "Service: $unitName", "Executes from writable path") `
                    -Recommendation "Move the executable to a root-owned directory with restricted permissions." `
                    -MITRE "T1053.006" `
                    -CVSSv3Score '7.8' `
                    -TechnicalImpact 'Systemd timers executing from writable paths allow local users to replace the binary for privilege escalation on the next timer trigger.'))
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
        -Recommendation "Review all custom services for legitimacy" `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    return $findings.ToArray()
}
