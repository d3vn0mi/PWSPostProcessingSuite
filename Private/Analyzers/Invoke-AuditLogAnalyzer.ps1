function Invoke-AuditLogAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Linux audit logs (auditd) for suspicious activity.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $auditFiles = @('/var/log/audit/audit.log', '/var/log/audit/audit.log.1')
    $allLines = [System.Collections.Generic.List[string]]::new()

    foreach ($logFile in $auditFiles) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $logFile
        if (Test-Path $resolved) {
            $lines = Read-ArtifactContent -Path $resolved
            foreach ($l in $lines) { $allLines.Add($l) }
        }
    }

    if ($allLines.Count -eq 0) { return @() }

    $execveEvents = [System.Collections.Generic.List[string]]::new()
    $privEscEvents = [System.Collections.Generic.List[string]]::new()
    $fileAccessEvents = [System.Collections.Generic.List[string]]::new()
    $userAuthEvents = [System.Collections.Generic.List[string]]::new()
    $anomalyEvents = [System.Collections.Generic.List[string]]::new()

    $sensitiveFiles = @('/etc/shadow', '/etc/passwd', '/etc/sudoers', '/etc/ssh/sshd_config', '/root/.ssh', '/etc/crontab')

    foreach ($line in $allLines) {
        # EXECVE events - command execution
        if ($line -match 'type=EXECVE') {
            # Check for suspicious commands
            $suspiciousPatterns = @('nc\s+-', 'ncat\s+-', '/dev/tcp/', 'base64.*-d', 'python.*-c', 'perl.*-e', 'wget.*\|', 'curl.*\|')
            foreach ($pattern in $suspiciousPatterns) {
                if ($line -match $pattern) {
                    $execveEvents.Add($line)
                    break
                }
            }
        }

        # Privilege escalation events
        if ($line -match 'type=USER_AUTH.*acct="root"' -or $line -match 'type=USER_CMD' -or
            $line -match 'type=ANOM_ABEND' -or $line -match 'type=ANOM_PROMISCUOUS') {
            $privEscEvents.Add($line)
        }

        # File access to sensitive files
        foreach ($sf in $sensitiveFiles) {
            if ($line -match [regex]::Escape($sf) -and $line -match 'type=(PATH|SYSCALL|OPENAT)') {
                $fileAccessEvents.Add($line)
                break
            }
        }

        # User authentication changes
        if ($line -match 'type=(ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP|USER_MGMT|GRP_MGMT|CHGRP_ID|CHUSER_ID)') {
            $userAuthEvents.Add($line)
        }

        # Anomaly events
        if ($line -match 'type=ANOM_') {
            $anomalyEvents.Add($line)
        }
    }

    # Suspicious command execution
    if ($execveEvents.Count -gt 0) {
        $findings.Add((New-Finding -Id "AUDIT-001" -Severity "High" -Category "Audit Log" `
            -Title "Suspicious command execution in audit log ($($execveEvents.Count) events)" `
            -Description "Audit log contains EXECVE records matching suspicious command patterns (reverse shells, encoded commands, etc.)." `
            -ArtifactPath "/var/log/audit/audit.log" `
            -Evidence @($execveEvents | Select-Object -First 10) `
            -Recommendation "Investigate each suspicious command execution and correlate with user sessions" `
            -MITRE "T1059"))
    }

    # Sensitive file access
    if ($fileAccessEvents.Count -gt 0) {
        $findings.Add((New-Finding -Id "AUDIT-002" -Severity "Medium" -Category "Audit Log" `
            -Title "Access to sensitive files detected ($($fileAccessEvents.Count) events)" `
            -Description "Audit log shows access to sensitive system files (shadow, sudoers, SSH config, etc.)." `
            -ArtifactPath "/var/log/audit/audit.log" `
            -Evidence @($fileAccessEvents | Select-Object -First 10) `
            -Recommendation "Review who accessed these files and whether it was authorized" `
            -MITRE "T1005"))
    }

    # User/group modifications
    if ($userAuthEvents.Count -gt 0) {
        $findings.Add((New-Finding -Id "AUDIT-003" -Severity "Medium" -Category "Audit Log" `
            -Title "User/group modifications detected ($($userAuthEvents.Count) events)" `
            -Description "Audit log shows user or group management events (additions, deletions, modifications)." `
            -ArtifactPath "/var/log/audit/audit.log" `
            -Evidence @($userAuthEvents | Select-Object -First 10) `
            -Recommendation "Verify all user/group changes were authorized" `
            -MITRE "T1136"))
    }

    # Anomaly events
    if ($anomalyEvents.Count -gt 0) {
        $findings.Add((New-Finding -Id "AUDIT-004" -Severity "High" -Category "Audit Log" `
            -Title "Audit anomaly events detected ($($anomalyEvents.Count))" `
            -Description "Anomaly events in the audit log indicate unusual system behavior (abnormal terminations, promiscuous mode, etc.)." `
            -ArtifactPath "/var/log/audit/audit.log" `
            -Evidence @($anomalyEvents | Select-Object -First 10) `
            -Recommendation "Investigate each anomaly event for signs of compromise" `
            -MITRE "T1068"))
    }

    # Summary
    $findings.Add((New-Finding -Id "AUDIT-INFO" -Severity "Informational" -Category "Audit Log" `
        -Title "Audit log analysis summary" `
        -Description "Analyzed $($allLines.Count) audit log entries." `
        -ArtifactPath "/var/log/audit/audit.log" `
        -Evidence @("Total entries: $($allLines.Count)", "Suspicious exec: $($execveEvents.Count)", "File access: $($fileAccessEvents.Count)", "User mgmt: $($userAuthEvents.Count)", "Anomalies: $($anomalyEvents.Count)") `
        -Recommendation "Correlate audit findings with other log sources"))

    return $findings.ToArray()
}
