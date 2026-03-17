function Invoke-LogIntegrityAnalyzer {
    <#
    .SYNOPSIS
        Analyzes log files for signs of tampering, clearing, or suspicious gaps.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $logDir = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/var/log'
    if (-not (Test-Path $logDir -PathType Container)) { return @() }

    # Check for empty/truncated log files
    $logFiles = Get-ChildItem -Path $logDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(log|1|2|gz)$' -or $_.Name -in @('syslog', 'messages', 'auth.log', 'secure', 'kern.log', 'cron', 'daemon.log', 'wtmp', 'btmp', 'lastlog') }

    $emptyLogs = $logFiles | Where-Object { $_.Length -eq 0 }
    $importantLogs = @('auth.log', 'secure', 'syslog', 'messages', 'kern.log', 'audit.log', 'wtmp', 'btmp')

    foreach ($emptyLog in $emptyLogs) {
        $severity = if ($emptyLog.Name -in $importantLogs) { 'High' } else { 'Medium' }
        $findings.Add((New-Finding -Id "LOGINT-001" -Severity $severity -Category "Log Integrity" `
            -Title "Empty log file: $($emptyLog.Name)" `
            -Description "Log file $($emptyLog.Name) is empty (0 bytes). This may indicate the log was cleared by an attacker." `
            -ArtifactPath "/var/log/$($emptyLog.Name)" `
            -Evidence @("File size: 0 bytes") `
            -Recommendation "Investigate why this log file is empty. Check for log rotation or deliberate clearing." `
            -MITRE "T1070.002" `
            -CVSSv3Score $(if ($severity -eq 'High') { '7.5' } else { '5.3' }) `
            -TechnicalImpact "Log clearing destroys forensic evidence, allowing attacker activity to go undetected and hindering incident response"))
    }

    # Check for time gaps in syslog-format logs
    $timeGapThresholdMinutes = 60
    $syslogFiles = @('syslog', 'messages', 'auth.log', 'secure')

    foreach ($logName in $syslogFiles) {
        $logPath = Join-Path $logDir $logName
        if (-not (Test-Path $logPath)) { continue }

        $lines = Read-ArtifactContent -Path $logPath
        if ($lines.Count -lt 2) { continue }

        $previousTimestamp = $null
        $gaps = [System.Collections.Generic.List[PSCustomObject]]::new()
        $currentYear = (Get-Date).Year

        foreach ($line in $lines) {
            # Parse syslog timestamp: "Mon DD HH:MM:SS"
            if ($line -match '^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})') {
                try {
                    $tsString = "$($Matches[1]) $currentYear"
                    $currentTimestamp = [datetime]::ParseExact($tsString, 'MMM  d HH:mm:ss yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                catch {
                    try {
                        $tsString = "$($Matches[1]) $currentYear"
                        $currentTimestamp = [datetime]::ParseExact($tsString, 'MMM dd HH:mm:ss yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
                    }
                    catch {
                        continue
                    }
                }

                if ($null -ne $previousTimestamp) {
                    $gap = $currentTimestamp - $previousTimestamp
                    if ($gap.TotalMinutes -gt $timeGapThresholdMinutes) {
                        $gaps.Add([PSCustomObject]@{
                            Start    = $previousTimestamp
                            End      = $currentTimestamp
                            Duration = $gap
                        })
                    }
                }
                $previousTimestamp = $currentTimestamp
            }
        }

        if ($gaps.Count -gt 0) {
            $severity = if ($gaps | Where-Object { $_.Duration.TotalHours -gt 24 }) { 'High' } else { 'Medium' }
            $findings.Add((New-Finding -Id "LOGINT-002" -Severity $severity -Category "Log Integrity" `
                -Title "Time gaps detected in $logName ($($gaps.Count) gaps)" `
                -Description "Significant time gaps were found in $logName. Gaps longer than $timeGapThresholdMinutes minutes may indicate log tampering or system downtime." `
                -ArtifactPath "/var/log/$logName" `
                -Evidence @($gaps | Select-Object -First 5 | ForEach-Object { "Gap: $($_.Start) to $($_.End) ($($_.Duration.TotalHours.ToString('F1')) hours)" }) `
                -Recommendation "Correlate gaps with system uptime records. Investigate if gaps align with suspicious activity." `
                -MITRE "T1070.002" `
                -CVSSv3Score $(if ($severity -eq 'High') { '7.5' } else { '5.3' }) `
                -TechnicalImpact "Time gaps in logs may indicate selective log tampering to conceal attacker actions during specific time windows"))
        }
    }

    # Check for very recent log start on what should be a long-running system
    foreach ($logName in $syslogFiles) {
        $logPath = Join-Path $logDir $logName
        if (-not (Test-Path $logPath)) { continue }

        $lines = Read-ArtifactContent -Path $logPath
        if ($lines.Count -lt 10) {
            $findings.Add((New-Finding -Id "LOGINT-003" -Severity "High" -Category "Log Integrity" `
                -Title "Very few entries in $logName ($($lines.Count) lines)" `
                -Description "The log file $logName has very few entries. If this is a production system, the log may have been recently cleared." `
                -ArtifactPath "/var/log/$logName" `
                -Evidence @("Total lines: $($lines.Count)") `
                -Recommendation "Check log rotation config and compare with expected log volume" `
                -MITRE "T1070.002" `
                -CVSSv3Score '7.5' `
                -TechnicalImpact "Recently cleared logs indicate active anti-forensics, destroying evidence of attacker activity and compromising incident response capability"))
        }
    }

    # Check for missing important log files
    foreach ($logName in $importantLogs) {
        $logPath = Join-Path $logDir $logName
        if (-not (Test-Path $logPath)) {
            # Check if rotated version exists
            $rotatedPath = Join-Path $logDir "${logName}.1"
            if (-not (Test-Path $rotatedPath)) {
                $findings.Add((New-Finding -Id "LOGINT-004" -Severity "Medium" -Category "Log Integrity" `
                    -Title "Important log file missing: $logName" `
                    -Description "The log file $logName was not found in the evidence. It may not have been collected, or it may have been deleted." `
                    -ArtifactPath "/var/log/$logName" `
                    -Evidence @("File not found: /var/log/$logName") `
                    -Recommendation "Verify if the log file exists on the source system. Its absence may indicate tampering." `
                    -MITRE "T1070.002" `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact "Missing log file may indicate deletion to cover attacker tracks, reducing ability to detect and investigate compromise"))
            }
        }
    }

    return $findings.ToArray()
}
