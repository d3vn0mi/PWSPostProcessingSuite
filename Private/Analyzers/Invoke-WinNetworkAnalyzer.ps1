function Invoke-WinNetworkAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows network configuration and connections for security issues.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known bad / C2 ports
    $suspiciousPorts = @(4444, 5555, 1337, 31337, 6666, 6667, 9001, 9002, 1234, 12345, 54321, 4443, 2222, 8888, 3333)
    if ($Rules.ContainsKey('c2_ports') -and $Rules['c2_ports'] -is [array]) {
        $suspiciousPorts = @($Rules['c2_ports'] | ForEach-Object { [int]$_ })
    }

    # Suspicious processes that should not normally make external connections
    $suspiciousProcesses = @('powershell', 'pwsh', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin', 'msiexec')

    # Well-known public DNS servers
    $knownPublicDNS = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '4.2.2.1', '4.2.2.2')

    # Helper to check if an IP is private/local
    function Test-PrivateIP {
        param([string]$IP)
        if ([string]::IsNullOrWhiteSpace($IP)) { return $true }
        if ($IP -eq '0.0.0.0' -or $IP -eq '127.0.0.1' -or $IP -eq '::' -or $IP -eq '::1' -or $IP -eq '*') { return $true }
        if ($IP -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|fe80)') { return $true }
        return $false
    }

    # Collect parsed connection objects from multiple sources
    $connections = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ----------------------------------------------------------------
    # Parse netstat.txt (format: Proto  LocalAddress  ForeignAddress  State  PID)
    # ----------------------------------------------------------------
    $netstatPath = Join-Path $EvidencePath 'network/netstat.txt'
    if (Test-Path $netstatPath) {
        $netstatLines = Read-ArtifactContent -Path $netstatPath
        foreach ($line in $netstatLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($trimmed -match '^\s*Proto' -or $trimmed -match '^Active' -or $trimmed -match '^=') { continue }

            # TCP    192.168.1.5:49234    203.0.113.5:443    ESTABLISHED    1234
            if ($trimmed -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\w+)?\s*(\d+)?\s*$') {
                $proto = $Matches[1]
                $localAddr = $Matches[2]
                $foreignAddr = $Matches[3]
                $state = if ($Matches[4]) { $Matches[4] } else { '' }
                $pid = if ($Matches[5]) { $Matches[5] } else { '' }

                $localIP = ''
                $localPort = 0
                $remoteIP = ''
                $remotePort = 0

                if ($localAddr -match '^(.+):(\d+)$') {
                    $localIP = $Matches[1]
                    $localPort = [int]$Matches[2]
                }
                if ($foreignAddr -match '^(.+):(\d+)$') {
                    $remoteIP = $Matches[1]
                    $remotePort = [int]$Matches[2]
                }

                $connections.Add([PSCustomObject]@{
                    Proto       = $proto
                    LocalIP     = $localIP
                    LocalPort   = $localPort
                    RemoteIP    = $remoteIP
                    RemotePort  = $remotePort
                    State       = $state
                    PID         = $pid
                    ProcessName = ''
                    Source      = 'netstat.txt'
                    RawLine     = $trimmed
                })
            }
        }
    }

    # ----------------------------------------------------------------
    # Parse tcp_connections.csv (from Get-NetTCPConnection)
    # ----------------------------------------------------------------
    $tcpCsvPath = Join-Path $EvidencePath 'network/tcp_connections.csv'
    if (Test-Path $tcpCsvPath) {
        try {
            $tcpRecords = Import-Csv -Path $tcpCsvPath -ErrorAction Stop
            foreach ($rec in $tcpRecords) {
                $localPort = 0
                $remotePort = 0
                $owningProcess = ''
                $processName = ''

                if ($rec.PSObject.Properties['LocalPort']) { [int]::TryParse($rec.LocalPort, [ref]$localPort) | Out-Null }
                if ($rec.PSObject.Properties['RemotePort']) { [int]::TryParse($rec.RemotePort, [ref]$remotePort) | Out-Null }
                if ($rec.PSObject.Properties['OwningProcess']) { $owningProcess = $rec.OwningProcess }
                if ($rec.PSObject.Properties['ProcessName']) { $processName = $rec.ProcessName }

                $connections.Add([PSCustomObject]@{
                    Proto       = 'TCP'
                    LocalIP     = if ($rec.PSObject.Properties['LocalAddress']) { $rec.LocalAddress } else { '' }
                    LocalPort   = $localPort
                    RemoteIP    = if ($rec.PSObject.Properties['RemoteAddress']) { $rec.RemoteAddress } else { '' }
                    RemotePort  = $remotePort
                    State       = if ($rec.PSObject.Properties['State']) { $rec.State } else { '' }
                    PID         = $owningProcess
                    ProcessName = $processName
                    Source      = 'tcp_connections.csv'
                    RawLine     = "$($rec.LocalAddress):$localPort -> $($rec.RemoteAddress):$remotePort [$($rec.State)] PID=$owningProcess"
                })
            }
        }
        catch {
            Write-Verbose "Failed to parse tcp_connections.csv: $_"
        }
    }

    # ----------------------------------------------------------------
    # WNET-001: Connection to known bad port
    # ----------------------------------------------------------------
    $badPortConnections = @()
    foreach ($conn in $connections) {
        if ($conn.RemotePort -in $suspiciousPorts -and $conn.State -match 'ESTABLISHED|Established|ESTAB') {
            $badPortConnections += $conn.RawLine
        }
        if ($conn.LocalPort -in $suspiciousPorts -and $conn.State -match 'LISTEN|Listen|ESTABLISHED|Established|ESTAB') {
            $badPortConnections += $conn.RawLine
        }
    }

    if ($badPortConnections.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WNET-001' -Severity 'High' -Category 'Network' `
            -Title 'Connections on known suspicious/C2 ports detected' `
            -Description "Found $($badPortConnections.Count) connection(s) involving known bad ports (4444, 5555, 1337, 31337, etc.) commonly associated with reverse shells and C2 frameworks." `
            -ArtifactPath 'network/netstat.txt' `
            -Evidence @($badPortConnections | Select-Object -First 15) `
            -Recommendation 'Investigate all connections on suspicious ports immediately. Identify the associated processes and block at the firewall level.' `
            -MITRE 'T1571' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Active connections on known C2 ports indicate potential command-and-control communication or reverse shell activity.'))
    }

    # ----------------------------------------------------------------
    # WNET-002: Multiple established connections to same external IP (beaconing)
    # ----------------------------------------------------------------
    $externalEstablished = $connections | Where-Object {
        $_.State -match 'ESTABLISHED|Established|ESTAB' -and -not (Test-PrivateIP $_.RemoteIP)
    }

    $groupedByRemoteIP = $externalEstablished | Group-Object -Property RemoteIP | Where-Object { $_.Count -ge 3 }
    if ($groupedByRemoteIP.Count -gt 0) {
        $beaconingEvidence = @()
        foreach ($group in $groupedByRemoteIP) {
            $beaconingEvidence += "$($group.Name): $($group.Count) established connections"
            $beaconingEvidence += ($group.Group | Select-Object -First 3 | ForEach-Object { "  $_($_.RawLine)" })
        }

        $findings.Add((New-Finding -Id 'WNET-002' -Severity 'Medium' -Category 'Network' `
            -Title 'Multiple established connections to same external IP detected' `
            -Description "Found $($groupedByRemoteIP.Count) external IP(s) with 3 or more established connections. This pattern may indicate C2 beaconing or data exfiltration." `
            -ArtifactPath 'network/tcp_connections.csv' `
            -Evidence @($beaconingEvidence | Select-Object -First 15) `
            -Recommendation 'Investigate the remote IP addresses for reputation. Correlate with process information and DNS queries to determine legitimacy.' `
            -MITRE 'T1071.001' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Multiple connections to the same external host may indicate command-and-control beaconing or persistent data exfiltration channels.'))
    }

    # ----------------------------------------------------------------
    # WNET-003: Process listening on suspicious port
    # ----------------------------------------------------------------
    $listeningOnSuspicious = @()
    foreach ($conn in $connections) {
        if ($conn.State -match 'LISTEN|Listen' -and $conn.LocalPort -in $suspiciousPorts) {
            $listeningOnSuspicious += $conn.RawLine
        }
    }

    if ($listeningOnSuspicious.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WNET-003' -Severity 'High' -Category 'Network' `
            -Title 'Process listening on suspicious port' `
            -Description "Found $($listeningOnSuspicious.Count) listener(s) on known suspicious ports. These ports are commonly used by malware, reverse shells, or C2 implants." `
            -ArtifactPath 'network/netstat.txt' `
            -Evidence @($listeningOnSuspicious | Select-Object -First 10) `
            -Recommendation 'Identify the process listening on each suspicious port. Verify legitimacy and terminate if unauthorized.' `
            -MITRE 'T1571' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Listeners on known malicious ports suggest the system may be running a backdoor or C2 implant accepting inbound connections.'))
    }

    # ----------------------------------------------------------------
    # WNET-004: DNS server pointing to non-standard address
    # ----------------------------------------------------------------
    $dnsCsvPath = Join-Path $EvidencePath 'network/dns_servers.csv'
    $ipconfigPath = Join-Path $EvidencePath 'network/ipconfig.txt'
    $nonStandardDNS = @()

    if (Test-Path $dnsCsvPath) {
        try {
            $dnsRecords = Import-Csv -Path $dnsCsvPath -ErrorAction Stop
            foreach ($rec in $dnsRecords) {
                $dnsAddr = ''
                if ($rec.PSObject.Properties['ServerAddresses']) { $dnsAddr = $rec.ServerAddresses }
                elseif ($rec.PSObject.Properties['Address']) { $dnsAddr = $rec.Address }
                elseif ($rec.PSObject.Properties['DNSServer']) { $dnsAddr = $rec.DNSServer }

                if (-not [string]::IsNullOrWhiteSpace($dnsAddr)) {
                    # Split in case multiple addresses in one field
                    foreach ($addr in ($dnsAddr -split '[,;{}\s]+')) {
                        $addr = $addr.Trim()
                        if ([string]::IsNullOrWhiteSpace($addr)) { continue }
                        if ($addr -notin $knownPublicDNS -and -not (Test-PrivateIP $addr)) {
                            $nonStandardDNS += $addr
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Failed to parse dns_servers.csv: $_"
        }
    }

    # Also check ipconfig output for DNS servers
    if (Test-Path $ipconfigPath) {
        $ipconfigLines = Read-ArtifactContent -Path $ipconfigPath
        foreach ($line in $ipconfigLines) {
            if ($line -match 'DNS Servers.*?:\s*(\d+\.\d+\.\d+\.\d+)') {
                $dnsIP = $Matches[1]
                if ($dnsIP -notin $knownPublicDNS -and -not (Test-PrivateIP $dnsIP)) {
                    $nonStandardDNS += $dnsIP
                }
            }
        }
    }

    $nonStandardDNS = @($nonStandardDNS | Select-Object -Unique)
    if ($nonStandardDNS.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WNET-004' -Severity 'Medium' -Category 'Network' `
            -Title 'DNS server pointing to non-standard address' `
            -Description "Found $($nonStandardDNS.Count) DNS server address(es) that are not well-known public DNS or private/local addresses. These could be rogue DNS servers used for traffic interception." `
            -ArtifactPath 'network/dns_servers.csv' `
            -Evidence @($nonStandardDNS | ForEach-Object { "DNS Server: $_" }) `
            -Recommendation 'Verify DNS server addresses are legitimate organizational DNS servers. Rogue DNS can redirect traffic to attacker-controlled infrastructure.' `
            -MITRE 'T1584.002' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Non-standard DNS servers can redirect domain resolution to attacker-controlled IPs, enabling credential theft, phishing, and malware delivery.'))
    }

    # ----------------------------------------------------------------
    # WNET-005: Multiple network interfaces (potential pivoting)
    # ----------------------------------------------------------------
    $interfaceCount = 0
    $interfaceEvidence = @()

    if (Test-Path $ipconfigPath) {
        $ipconfigLines = Read-ArtifactContent -Path $ipconfigPath
        $currentAdapter = ''
        $adapterIPs = @()

        foreach ($line in $ipconfigLines) {
            if ($line -match '^(\S.+)adapter\s+(.+):') {
                $currentAdapter = $Matches[2].Trim()
            }
            if ($line -match 'IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)') {
                $ip = $Matches[1]
                if ($ip -ne '127.0.0.1') {
                    $interfaceCount++
                    $interfaceEvidence += "$currentAdapter : $ip"
                }
            }
        }
    }

    if ($interfaceCount -ge 2) {
        $findings.Add((New-Finding -Id 'WNET-005' -Severity 'Medium' -Category 'Network' `
            -Title "Multiple network interfaces detected ($interfaceCount)" `
            -Description "The system has $interfaceCount active network interfaces with assigned IPv4 addresses. Multiple interfaces increase the attack surface and may indicate potential for network pivoting or MitM attacks." `
            -ArtifactPath 'network/ipconfig.txt' `
            -Evidence @($interfaceEvidence | Select-Object -First 10) `
            -Recommendation 'Verify all network interfaces are authorized. Disable unused interfaces to reduce attack surface. Monitor for lateral movement if dual-homed.' `
            -MITRE 'T1599' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Multiple network interfaces may allow an attacker to pivot between network segments or perform man-in-the-middle attacks.'))
    }

    # ----------------------------------------------------------------
    # WNET-006: Connection from unusual process to external IP
    # ----------------------------------------------------------------
    $suspiciousProcessConnections = @()
    foreach ($conn in $connections) {
        if (-not [string]::IsNullOrWhiteSpace($conn.ProcessName) -and -not (Test-PrivateIP $conn.RemoteIP) -and $conn.State -match 'ESTABLISHED|Established|ESTAB') {
            $procLower = $conn.ProcessName.ToLower() -replace '\.exe$', ''
            if ($procLower -in $suspiciousProcesses) {
                $suspiciousProcessConnections += "Process=$($conn.ProcessName) PID=$($conn.PID) -> $($conn.RemoteIP):$($conn.RemotePort)"
            }
        }
    }

    if ($suspiciousProcessConnections.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WNET-006' -Severity 'High' -Category 'Network' `
            -Title 'Suspicious process connected to external IP' `
            -Description "Found $($suspiciousProcessConnections.Count) connection(s) from suspicious processes (powershell, cmd, rundll32, etc.) to external IP addresses. These processes should not normally initiate external network connections." `
            -ArtifactPath 'network/tcp_connections.csv' `
            -Evidence @($suspiciousProcessConnections | Select-Object -First 15) `
            -Recommendation 'Investigate each suspicious process connection immediately. Check for malicious payloads, download cradles, or C2 communication.' `
            -MITRE 'T1059' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Processes like PowerShell or cmd connecting externally often indicate active exploitation, download cradles, or command-and-control activity.'))
    }

    # ----------------------------------------------------------------
    # WNET-007: IPv6 enabled (increased attack surface)
    # ----------------------------------------------------------------
    $ipv6Enabled = $false
    $ipv6Evidence = @()

    if (Test-Path $ipconfigPath) {
        $ipconfigLines = Read-ArtifactContent -Path $ipconfigPath
        foreach ($line in $ipconfigLines) {
            if ($line -match 'IPv6 Address.*?:\s*([0-9a-fA-F:]+)' -and $line -notmatch 'fe80::') {
                $ipv6Enabled = $true
                $ipv6Evidence += $line.Trim()
            }
            if ($line -match 'Temporary IPv6') {
                $ipv6Enabled = $true
                $ipv6Evidence += $line.Trim()
            }
        }
    }

    # Check connections for IPv6 activity
    $ipv6Connections = $connections | Where-Object { $_.LocalIP -match ':' -or $_.RemoteIP -match ':' }
    if ($ipv6Connections.Count -gt 0) {
        $ipv6Enabled = $true
        $ipv6Evidence += "IPv6 connections found: $($ipv6Connections.Count)"
    }

    if ($ipv6Enabled) {
        $findings.Add((New-Finding -Id 'WNET-007' -Severity 'Low' -Category 'Network' `
            -Title 'IPv6 is enabled on the system' `
            -Description 'IPv6 is enabled and active on this system. If IPv6 is not actively managed and monitored, it increases the attack surface and may bypass IPv4-only security controls.' `
            -ArtifactPath 'network/ipconfig.txt' `
            -Evidence @($ipv6Evidence | Select-Object -First 10) `
            -Recommendation 'If IPv6 is not required, disable it to reduce attack surface. If required, ensure firewall rules and monitoring cover IPv6 traffic.' `
            -MITRE 'T1595' `
            -CVSSv3Score '3.1' `
            -TechnicalImpact 'IPv6 may bypass IPv4-only firewall rules and IDS/IPS systems, allowing attackers an unmonitored communication channel.'))
    }

    # ----------------------------------------------------------------
    # WNET-008: Network summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()

    $totalConnections = $connections.Count
    $established = @($connections | Where-Object { $_.State -match 'ESTABLISHED|Established|ESTAB' }).Count
    $listening = @($connections | Where-Object { $_.State -match 'LISTEN|Listen' }).Count
    $externalCount = @($connections | Where-Object { -not (Test-PrivateIP $_.RemoteIP) -and $_.State -match 'ESTABLISHED|Established|ESTAB' }).Count

    $summaryItems += "Total connections parsed: $totalConnections"
    $summaryItems += "Established connections: $established"
    $summaryItems += "Listening ports: $listening"
    $summaryItems += "External established connections: $externalCount"
    $summaryItems += "Network interfaces with IPv4: $interfaceCount"
    $summaryItems += "IPv6 active: $(if ($ipv6Enabled) { 'Yes' } else { 'No' })"
    $summaryItems += "Non-standard DNS servers: $($nonStandardDNS.Count)"

    # ARP table summary
    $arpPath = Join-Path $EvidencePath 'network/arp_table.txt'
    if (Test-Path $arpPath) {
        $arpLines = Read-ArtifactContent -Path $arpPath
        $arpEntries = @($arpLines | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' -and $_ -notmatch 'Interface|Internet' })
        $summaryItems += "ARP table entries: $($arpEntries.Count)"
    }

    # Route table summary
    $routePath = Join-Path $EvidencePath 'network/route_table.txt'
    if (Test-Path $routePath) {
        $routeLines = Read-ArtifactContent -Path $routePath
        $routeEntries = @($routeLines | Where-Object { $_ -match '^\s*\d+\.\d+\.\d+\.\d+' })
        $summaryItems += "Route table entries: $($routeEntries.Count)"
    }

    # DNS cache summary
    $dnsCachePath = Join-Path $EvidencePath 'collected_commands/dns_cache.txt'
    if (Test-Path $dnsCachePath) {
        $dnsCacheLines = Read-ArtifactContent -Path $dnsCachePath
        $dnsEntries = @($dnsCacheLines | Where-Object { $_ -match 'Record Name' })
        $summaryItems += "DNS cache entries: $($dnsEntries.Count)"
    }

    $findings.Add((New-Finding -Id 'WNET-008' -Severity 'Informational' -Category 'Network' `
        -Title 'Network configuration and connections summary' `
        -Description 'Summary of network configuration, active connections, and related artifacts collected from the system.' `
        -ArtifactPath 'network/' `
        -Evidence $summaryItems `
        -Recommendation 'Review the network summary for anomalies and correlate with other findings.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of network posture.'))

    return $findings.ToArray()
}
