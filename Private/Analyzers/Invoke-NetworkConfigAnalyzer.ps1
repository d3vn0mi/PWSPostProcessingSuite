function Invoke-NetworkConfigAnalyzer {
    <#
    .SYNOPSIS
        Analyzes network configuration files for security issues.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Analyze /etc/hosts
    $hostsPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/hosts'
    if (Test-Path $hostsPath) {
        $hostsLines = Read-ArtifactContent -Path $hostsPath
        $suspiciousHosts = @()

        foreach ($line in $hostsLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            # Check for hosts file hijacking (redirecting legitimate domains)
            $parts = $trimmed -split '\s+', 2
            if ($parts.Count -ge 2) {
                $ip = $parts[0]
                $hostnames = $parts[1]

                # Suspicious: redirecting well-known domains to non-standard IPs
                $knownDomains = @('google.com', 'microsoft.com', 'windowsupdate.com', 'ubuntu.com', 'debian.org', 'github.com', 'api.github.com')
                foreach ($domain in $knownDomains) {
                    if ($hostnames -match [regex]::Escape($domain) -and $ip -ne '127.0.0.1' -and $ip -ne '::1') {
                        $suspiciousHosts += $trimmed
                    }
                }

                # Check for blocking security update servers
                if ($hostnames -match 'update|security|antivirus|kaspersky|malwarebytes|symantec|avast|avg|sophos' -and $ip -eq '127.0.0.1') {
                    $findings.Add((New-Finding -Id "NET-001" -Severity "High" -Category "Network" `
                        -Title "Security/update domain blocked via /etc/hosts" `
                        -Description "A security-related domain is being redirected to localhost, potentially blocking security updates." `
                        -ArtifactPath "/etc/hosts" `
                        -Evidence @($trimmed) `
                        -Recommendation "Remove the hosts file entry blocking security domains" `
                        -MITRE "T1562.001" `
                        -CVSSv3Score "7.5" `
                        -TechnicalImpact "Prevents security software updates, leaving the system vulnerable to known exploits and unpatched vulnerabilities."))
                }
            }
        }

        if ($suspiciousHosts.Count -gt 0) {
            $findings.Add((New-Finding -Id "NET-002" -Severity "High" -Category "Network" `
                -Title "Suspicious hosts file redirections detected" `
                -Description "The /etc/hosts file contains redirections of well-known domains to unexpected IP addresses. This could indicate DNS hijacking." `
                -ArtifactPath "/etc/hosts" `
                -Evidence $suspiciousHosts `
                -Recommendation "Review and remove unauthorized hosts file entries" `
                -MITRE "T1565.001" `
                -CVSSv3Score "8.1" `
                -TechnicalImpact "Allows attacker to redirect traffic for well-known domains to malicious servers, enabling credential theft or malware delivery."))
        }
    }

    # Analyze /etc/resolv.conf
    $resolvPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/resolv.conf'
    if (Test-Path $resolvPath) {
        $resolvLines = Read-ArtifactContent -Path $resolvPath
        $nameservers = @()

        foreach ($line in $resolvLines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^\s*nameserver\s+(.+)') {
                $nameservers += $Matches[1].Trim()
            }
        }

        # Known public DNS for reference
        $knownDNS = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220', '127.0.0.53', '127.0.0.1')

        $unknownDNS = $nameservers | Where-Object { $_ -notin $knownDNS -and $_ -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' }
        if ($unknownDNS) {
            $findings.Add((New-Finding -Id "NET-003" -Severity "Medium" -Category "Network" `
                -Title "Non-standard DNS nameservers configured" `
                -Description "The system uses DNS nameservers that are not well-known public DNS or RFC1918 addresses. Verify these are legitimate organizational DNS servers." `
                -ArtifactPath "/etc/resolv.conf" `
                -Evidence @($unknownDNS | ForEach-Object { "nameserver $_" }) `
                -Recommendation "Verify DNS nameservers are legitimate and authorized" `
                -MITRE "T1584.002" `
                -CVSSv3Score "5.3" `
                -TechnicalImpact "Rogue DNS servers can redirect traffic, intercept credentials, and deliver malware by resolving domains to attacker-controlled IPs."))
        }

        $findings.Add((New-Finding -Id "NET-INFO-DNS" -Severity "Informational" -Category "Network" `
            -Title "DNS configuration summary" `
            -Description "System configured with $($nameservers.Count) nameservers." `
            -ArtifactPath "/etc/resolv.conf" `
            -Evidence @($nameservers | ForEach-Object { "nameserver $_" }) `
            -Recommendation "Ensure DNS servers are trusted" `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    # Analyze /etc/hosts.allow and /etc/hosts.deny (TCP wrappers)
    $hostsAllowPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/hosts.allow'
    $hostsDenyPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/hosts.deny'

    if (Test-Path $hostsDenyPath) {
        $denyLines = Read-ArtifactContent -Path $hostsDenyPath
        $hasDefaultDeny = $denyLines | Where-Object { $_ -match '^\s*ALL\s*:\s*ALL' }
        if (-not $hasDefaultDeny) {
            $findings.Add((New-Finding -Id "NET-004" -Severity "Low" -Category "Network" `
                -Title "No default deny in /etc/hosts.deny" `
                -Description "TCP Wrappers does not have a default deny-all rule, meaning services not explicitly listed are accessible." `
                -ArtifactPath "/etc/hosts.deny" `
                -Evidence @("Missing 'ALL: ALL' default deny rule") `
                -Recommendation "Add 'ALL: ALL' to /etc/hosts.deny and explicitly allow in hosts.allow" `
                -MITRE "T1562.004" `
                -CVSSv3Score "3.1" `
                -TechnicalImpact "Without a default deny rule, network services may be accessible from unauthorized hosts, increasing the attack surface."))
        }
    }

    if (Test-Path $hostsAllowPath) {
        $allowLines = Read-ArtifactContent -Path $hostsAllowPath
        $allowEntries = $allowLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') }
        if ($allowEntries) {
            $findings.Add((New-Finding -Id "NET-INFO-TCPW" -Severity "Informational" -Category "Network" `
                -Title "TCP Wrappers allow rules" `
                -Description "Found $($allowEntries.Count) allow entries in hosts.allow." `
                -ArtifactPath "/etc/hosts.allow" `
                -Evidence @($allowEntries) `
                -Recommendation "Review allowed services and source addresses" `
                -CVSSv3Score '' `
                -TechnicalImpact ''))
        }
    }

    # Check for network interface configuration
    $interfacesPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/network/interfaces'
    if (Test-Path $interfacesPath) {
        $ifaceContent = (Read-ArtifactContent -Path $interfacesPath) -join "`n"

        # Check for pre-up/post-up scripts (can be persistence)
        if ($ifaceContent -match '(pre-up|post-up|pre-down|post-down)\s+') {
            $hookLines = (Read-ArtifactContent -Path $interfacesPath) | Where-Object { $_ -match '(pre-up|post-up|pre-down|post-down)\s+' }
            $findings.Add((New-Finding -Id "NET-005" -Severity "Medium" -Category "Network" `
                -Title "Network interface hook scripts configured" `
                -Description "Network interface configuration contains hook scripts that execute during interface state changes. These can be used for persistence." `
                -ArtifactPath "/etc/network/interfaces" `
                -Evidence @($hookLines) `
                -Recommendation "Verify network hook scripts are legitimate" `
                -MITRE "T1037" `
                -CVSSv3Score "5.3" `
                -TechnicalImpact "May allow attacker to maintain persistent access by executing malicious code whenever network interfaces are brought up or down."))
        }
    }

    # ----------------------------------------------------------------
    # NET-006: Proxy environment variables (potential MITM)
    # ----------------------------------------------------------------
    $envPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/environment'
    $proxyFiles = @()
    if (Test-Path $envPath -PathType Leaf) { $proxyFiles += Get-Item $envPath }
    $profileFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc/profile.d' -Filter '*.sh'
    foreach ($f in $profileFiles) { $proxyFiles += $f }

    foreach ($proxyFile in $proxyFiles) {
        $lines = Read-ArtifactContent -Path $proxyFile.FullName
        foreach ($line in $lines) {
            if ($line -match '(?i)(https?_proxy|ftp_proxy|all_proxy)\s*=\s*["\x27]?(\S+)') {
                $proxyVar = $Matches[1]
                $proxyValue = $Matches[2]
                $relativePath = $proxyFile.FullName.Replace($EvidencePath, '').TrimStart('/\')

                $findings.Add((New-Finding -Id "NET-006" -Severity "Medium" -Category "Network" `
                    -Title "Proxy environment variable set: $proxyVar" `
                    -Description "System-wide proxy variable '$proxyVar' is configured in '$relativePath'. All HTTP traffic will be routed through this proxy." `
                    -ArtifactPath $proxyFile.FullName `
                    -Evidence @("File: $relativePath", "$proxyVar=$proxyValue") `
                    -Recommendation "Verify the proxy server is trusted and authorized. Rogue proxies enable man-in-the-middle attacks." `
                    -MITRE "T1557" `
                    -CVSSv3Score "5.3" `
                    -TechnicalImpact "System-wide proxy settings route all HTTP traffic through a specified server, enabling interception if the proxy is malicious."))
            }
        }
    }

    # ----------------------------------------------------------------
    # NET-007: Network interfaces in promiscuous mode
    # ----------------------------------------------------------------
    $ifconfigFiles = @()
    foreach ($pattern in @('ifconfig*', 'ip_addr*', 'ip_link*', 'network_interfaces*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $ifconfigFiles += $f }
    }

    foreach ($ifFile in $ifconfigFiles) {
        $content = (Read-ArtifactContent -Path $ifFile.FullName) -join "`n"
        if ($content -match 'PROMISC') {
            $promiscLines = (Read-ArtifactContent -Path $ifFile.FullName) | Where-Object { $_ -match 'PROMISC' }
            $findings.Add((New-Finding -Id "NET-007" -Severity "High" -Category "Network" `
                -Title "Network interface in promiscuous mode" `
                -Description "One or more network interfaces are in promiscuous mode, capturing all network traffic. This may indicate network sniffing." `
                -ArtifactPath $ifFile.FullName `
                -Evidence @($promiscLines | Select-Object -First 3) `
                -Recommendation "Investigate why interfaces are in promiscuous mode. This is expected for network monitoring tools but may indicate compromise." `
                -MITRE "T1040" `
                -CVSSv3Score "7.5" `
                -TechnicalImpact "Promiscuous mode enables capture of all network traffic on the segment, allowing credential interception and data exfiltration."))
        }
    }

    # ----------------------------------------------------------------
    # NET-008: Connections on known C2 ports
    # ----------------------------------------------------------------
    $c2Ports = @(4444, 5555, 1337, 31337, 6666, 6667, 9001, 9002, 1234, 12345, 54321, 4443, 2222)
    if ($Rules.ContainsKey('c2_ports') -and $Rules['c2_ports'] -is [array]) {
        $c2Ports = @($Rules['c2_ports'] | ForEach-Object { [int]$_ })
    }

    $netStatFiles = @()
    foreach ($pattern in @('ss_*', 'netstat*', 'ss-*', 'network_connections*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $netStatFiles += $f }
    }

    foreach ($netFile in $netStatFiles) {
        $lines = Read-ArtifactContent -Path $netFile.FullName
        foreach ($line in $lines) {
            foreach ($port in $c2Ports) {
                if ($line -match ":${port}\s" -and $line -match '(ESTAB|ESTABLISHED)') {
                    $findings.Add((New-Finding -Id "NET-008" -Severity "High" -Category "Network" `
                        -Title "Established connection on C2 port $port" `
                        -Description "An established network connection was found on port $port, commonly associated with command-and-control or reverse shell activity." `
                        -ArtifactPath $netFile.FullName `
                        -Evidence @($line.Trim()) `
                        -Recommendation "Investigate the process and remote endpoint immediately. Block the connection at the firewall level." `
                        -MITRE "T1571" `
                        -CVSSv3Score "8.1" `
                        -TechnicalImpact "Active connection on known C2 port suggests command-and-control communication or reverse shell activity."))
                    break
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # NET-009: Services listening on all interfaces (0.0.0.0)
    # ----------------------------------------------------------------
    $sensitiveListenPorts = @(3306, 5432, 6379, 27017, 9200, 11211, 8080, 8443, 2375, 2376)

    foreach ($netFile in $netStatFiles) {
        $lines = Read-ArtifactContent -Path $netFile.FullName
        foreach ($line in $lines) {
            if ($line -match 'LISTEN') {
                foreach ($port in $sensitiveListenPorts) {
                    if ($line -match "0\.0\.0\.0:${port}\s" -or $line -match "\*:${port}\s" -or $line -match ":::${port}\s") {
                        $serviceName = switch ($port) {
                            3306  { 'MySQL' }
                            5432  { 'PostgreSQL' }
                            6379  { 'Redis' }
                            27017 { 'MongoDB' }
                            9200  { 'Elasticsearch' }
                            11211 { 'Memcached' }
                            8080  { 'HTTP proxy/alt' }
                            8443  { 'HTTPS alt' }
                            2375  { 'Docker API (unencrypted)' }
                            2376  { 'Docker API (TLS)' }
                            default { "Port $port" }
                        }
                        $severity = if ($port -in @(6379, 27017, 9200, 11211, 2375)) { 'High' } else { 'Medium' }

                        $findings.Add((New-Finding -Id "NET-009" -Severity $severity -Category "Network" `
                            -Title "$serviceName listening on all interfaces (port $port)" `
                            -Description "$serviceName is listening on 0.0.0.0:$port, accepting connections from all network interfaces including external ones." `
                            -ArtifactPath $netFile.FullName `
                            -Evidence @($line.Trim()) `
                            -Recommendation "Bind $serviceName to localhost (127.0.0.1) or specific internal interfaces only. Use firewall rules to restrict access." `
                            -MITRE "T1190" `
                            -CVSSv3Score $(if ($severity -eq 'High') { '7.5' } else { '5.3' }) `
                            -TechnicalImpact "$serviceName exposed on all interfaces may be accessible from untrusted networks, enabling unauthorized data access or exploitation."))
                        break
                    }
                }
            }
        }
    }

    return $findings.ToArray()
}
