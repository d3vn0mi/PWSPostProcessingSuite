function Invoke-ProcessAnalyzer {
    <#
    .SYNOPSIS
        Analyzes collected process information for suspicious activity.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Look for process listing files (common collection formats)
    $processFiles = @()
    $searchPatterns = @('ps_*', 'processes*', 'ps-aux*', 'psaux*', 'running_processes*')
    foreach ($pattern in $searchPatterns) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $processFiles += $f }
    }

    # Also check /proc if collected
    $procPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc'

    $suspiciousPaths = @('/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/')
    $cryptoIndicators = @('xmrig', 'minerd', 'cpuminer', 'stratum', 'cryptonight', 'nicehash', 'minergate')

    foreach ($pFile in $processFiles) {
        $lines = Read-ArtifactContent -Path $pFile.FullName
        if ($lines.Count -eq 0) { continue }

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            # Check for processes running from suspicious paths
            foreach ($sp in $suspiciousPaths) {
                if ($trimmed -match [regex]::Escape($sp)) {
                    $findings.Add((New-Finding -Id "PROC-001" -Severity "High" -Category "Processes" `
                        -Title "Process running from suspicious path" `
                        -Description "A process is running from $sp which is a world-writable temporary directory." `
                        -ArtifactPath $pFile.Name `
                        -Evidence @($trimmed) `
                        -Recommendation "Investigate the process and binary in the temporary directory" `
                        -MITRE "T1059"))
                    break
                }
            }

            # Check for deleted binaries still running
            if ($trimmed -match '\(deleted\)' -or $trimmed -match '/\.~') {
                $findings.Add((New-Finding -Id "PROC-002" -Severity "Critical" -Category "Processes" `
                    -Title "Process running from deleted binary" `
                    -Description "A process is running from a binary that has been deleted from disk. This is a strong indicator of malicious activity - attackers often delete their binaries after execution." `
                    -ArtifactPath $pFile.Name `
                    -Evidence @($trimmed) `
                    -Recommendation "Capture the process memory and investigate. The binary can be recovered from /proc/[pid]/exe" `
                    -MITRE "T1070.004"))
            }

            # Check for crypto mining indicators
            foreach ($indicator in $cryptoIndicators) {
                if ($trimmed -match $indicator) {
                    $findings.Add((New-Finding -Id "PROC-003" -Severity "Critical" -Category "Processes" `
                        -Title "Crypto mining process detected: $indicator" `
                        -Description "A running process matches cryptocurrency mining indicators." `
                        -ArtifactPath $pFile.Name `
                        -Evidence @($trimmed) `
                        -Recommendation "Kill the mining process and investigate how it was deployed" `
                        -MITRE "T1496"))
                    break
                }
            }

            # Check for reverse shell processes
            if ($trimmed -match '/dev/tcp/' -or ($trimmed -match 'nc\s+' -and $trimmed -match '\s+-e\s+') -or
                $trimmed -match 'mkfifo' -or ($trimmed -match 'bash\s+-i' -and $trimmed -match '>&')) {
                $findings.Add((New-Finding -Id "PROC-004" -Severity "Critical" -Category "Processes" `
                    -Title "Possible reverse shell process detected" `
                    -Description "A running process matches reverse shell patterns." `
                    -ArtifactPath $pFile.Name `
                    -Evidence @($trimmed) `
                    -Recommendation "Immediately investigate this connection and identify the remote endpoint" `
                    -MITRE "T1059.004"))
            }
        }
    }

    # Analyze lsof output if available
    $lsofFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter 'lsof*'
    foreach ($lsFile in $lsofFiles) {
        $lines = Read-ArtifactContent -Path $lsFile.FullName
        foreach ($line in $lines) {
            # Check for deleted files being held open
            if ($line -match 'DEL\s+' -or $line -match '\(deleted\)') {
                if ($line -match '/tmp/|/dev/shm/|/var/tmp/') {
                    $findings.Add((New-Finding -Id "PROC-005" -Severity "High" -Category "Processes" `
                        -Title "Deleted file held open from suspicious location" `
                        -Description "A process has an open file handle to a deleted file in a temporary directory." `
                        -ArtifactPath $lsFile.Name `
                        -Evidence @($line.Trim()) `
                        -Recommendation "Investigate the process holding the deleted file" `
                        -MITRE "T1070.004"))
                }
            }
        }
    }

    # Analyze network connections (ss/netstat output)
    $netFiles = @()
    foreach ($pattern in @('ss_*', 'netstat*', 'ss-*', 'network_connections*', 'connections*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $netFiles += $f }
    }

    $knownBadPorts = @(4444, 5555, 1337, 31337, 6666, 6667, 9001)
    if ($Rules.ContainsKey('suspicious_network') -and $Rules['suspicious_network'] -is [hashtable]) {
        $sn = $Rules['suspicious_network']
        if ($sn.ContainsKey('known_bad_ports')) {
            $knownBadPorts = @($sn['known_bad_ports'] | ForEach-Object { [int]$_ })
        }
    }

    foreach ($netFile in $netFiles) {
        $lines = Read-ArtifactContent -Path $netFile.FullName
        foreach ($line in $lines) {
            foreach ($port in $knownBadPorts) {
                if ($line -match ":${port}\s" -and $line -match 'ESTAB') {
                    $findings.Add((New-Finding -Id "PROC-006" -Severity "High" -Category "Network Connections" `
                        -Title "Established connection on suspicious port $port" `
                        -Description "An established network connection was found on port $port, commonly associated with reverse shells or C2." `
                        -ArtifactPath $netFile.Name `
                        -Evidence @($line.Trim()) `
                        -Recommendation "Investigate the process and remote endpoint" `
                        -MITRE "T1571"))
                    break
                }
            }
        }
    }

    return $findings.ToArray()
}
