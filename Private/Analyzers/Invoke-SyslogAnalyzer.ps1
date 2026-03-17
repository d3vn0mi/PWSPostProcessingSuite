function Invoke-SyslogAnalyzer {
    <#
    .SYNOPSIS
        Analyzes syslog/messages for kernel events, crashes, and suspicious activity.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $logFiles = @('/var/log/syslog', '/var/log/syslog.1', '/var/log/messages', '/var/log/messages.1', '/var/log/kern.log', '/var/log/kern.log.1')
    $allLines = [System.Collections.Generic.List[string]]::new()

    foreach ($logFile in $logFiles) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $logFile
        if (Test-Path $resolved) {
            $lines = Read-ArtifactContent -Path $resolved
            foreach ($l in $lines) { $allLines.Add($l) }
        }
    }

    if ($allLines.Count -eq 0) { return @() }

    $segfaults = [System.Collections.Generic.List[string]]::new()
    $oomKills = [System.Collections.Generic.List[string]]::new()
    $kernelPanics = [System.Collections.Generic.List[string]]::new()
    $usbEvents = [System.Collections.Generic.List[string]]::new()
    $moduleLoads = [System.Collections.Generic.List[string]]::new()
    $promiscMode = [System.Collections.Generic.List[string]]::new()

    foreach ($line in $allLines) {
        # Segfaults (potential exploitation)
        if ($line -match 'segfault at|general protection fault|traps:.*trap') {
            $segfaults.Add($line)
        }

        # OOM kills
        if ($line -match 'Out of memory|oom-killer|oom_kill_process') {
            $oomKills.Add($line)
        }

        # Kernel panics
        if ($line -match 'Kernel panic|BUG:|kernel BUG at|Oops:') {
            $kernelPanics.Add($line)
        }

        # USB device connections (data exfiltration vector)
        if ($line -match 'usb\s+\d+-\d+:.*new\s+(high|full|low)\s+speed' -or $line -match 'USB Mass Storage') {
            $usbEvents.Add($line)
        }

        # Kernel module loading
        if ($line -match 'module.*loaded|insmod|modprobe') {
            $moduleLoads.Add($line)
        }

        # Promiscuous mode (network sniffing)
        if ($line -match 'promiscuous mode|entered promiscuous') {
            $promiscMode.Add($line)
        }
    }

    # Report segfaults
    if ($segfaults.Count -gt 5) {
        $findings.Add((New-Finding -Id "SYSLOG-001" -Severity "High" -Category "System Events" `
            -Title "Repeated segmentation faults detected ($($segfaults.Count))" `
            -Description "Multiple segfaults were detected in system logs. This could indicate exploitation attempts, memory corruption, or unstable software." `
            -ArtifactPath "/var/log/syslog" `
            -Evidence @($segfaults | Select-Object -First 10) `
            -Recommendation "Investigate the processes causing segfaults for exploitation indicators" `
            -MITRE "T1203" `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Repeated segfaults may indicate active exploitation attempts that could lead to arbitrary code execution or denial of service.'))
    }
    elseif ($segfaults.Count -gt 0) {
        $findings.Add((New-Finding -Id "SYSLOG-001" -Severity "Medium" -Category "System Events" `
            -Title "Segmentation faults detected ($($segfaults.Count))" `
            -Description "Segfault events detected in system logs." `
            -ArtifactPath "/var/log/syslog" `
            -Evidence @($segfaults | Select-Object -First 5) `
            -Recommendation "Review segfaulting processes" `
            -MITRE "T1203" `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Segfaults may indicate exploitation attempts or unstable software that could be leveraged for code execution.'))
    }

    # OOM kills
    if ($oomKills.Count -gt 0) {
        $findings.Add((New-Finding -Id "SYSLOG-002" -Severity "Medium" -Category "System Events" `
            -Title "Out-of-memory kills detected ($($oomKills.Count))" `
            -Description "OOM killer was invoked, indicating memory exhaustion. This could be from a DoS attack, resource abuse, or crypto mining." `
            -ArtifactPath "/var/log/syslog" `
            -Evidence @($oomKills | Select-Object -First 5) `
            -Recommendation "Investigate what processes consumed excessive memory" `
            -MITRE "T1496" `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Memory exhaustion may indicate resource hijacking for cryptomining or denial-of-service attack against system availability.'))
    }

    # Kernel panics
    if ($kernelPanics.Count -gt 0) {
        $findings.Add((New-Finding -Id "SYSLOG-003" -Severity "High" -Category "System Events" `
            -Title "Kernel panics detected" `
            -Description "Kernel panics or BUG events were found in logs. This could indicate kernel exploitation attempts." `
            -ArtifactPath "/var/log/kern.log" `
            -Evidence @($kernelPanics | Select-Object -First 5) `
            -Recommendation "Investigate kernel panics for signs of exploitation" `
            -MITRE "T1068" `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Kernel panics may indicate kernel exploitation attempts that could lead to full system compromise or persistent denial of service.'))
    }

    # Promiscuous mode
    if ($promiscMode.Count -gt 0) {
        $findings.Add((New-Finding -Id "SYSLOG-004" -Severity "High" -Category "System Events" `
            -Title "Network interface entered promiscuous mode" `
            -Description "One or more network interfaces entered promiscuous mode, indicating packet capture/sniffing activity." `
            -ArtifactPath "/var/log/syslog" `
            -Evidence @($promiscMode | Select-Object -First 5) `
            -Recommendation "Identify what put the interface in promiscuous mode. Check for tcpdump, wireshark, or other sniffers." `
            -MITRE "T1040" `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Enables network traffic sniffing to capture credentials, session tokens, and sensitive data transmitted on the local network segment.'))
    }

    # USB events
    if ($usbEvents.Count -gt 0) {
        $findings.Add((New-Finding -Id "SYSLOG-005" -Severity "Informational" -Category "System Events" `
            -Title "USB device connections detected ($($usbEvents.Count))" `
            -Description "USB device connection events found in logs." `
            -ArtifactPath "/var/log/syslog" `
            -Evidence @($usbEvents | Select-Object -First 10) `
            -Recommendation "Review USB device connections for unauthorized data exfiltration" `
            -MITRE "T1052.001" `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    # Summary
    $findings.Add((New-Finding -Id "SYSLOG-INFO" -Severity "Informational" -Category "System Events" `
        -Title "Syslog analysis summary" `
        -Description "Analyzed $($allLines.Count) log lines. Found: $($segfaults.Count) segfaults, $($oomKills.Count) OOM kills, $($kernelPanics.Count) panics, $($promiscMode.Count) promiscuous mode events." `
        -ArtifactPath "/var/log/" `
        -Evidence @("Total lines: $($allLines.Count)") `
        -Recommendation "Review complete system logs for additional context" `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    return $findings.ToArray()
}
