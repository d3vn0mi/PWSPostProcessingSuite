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

    return $findings.ToArray()
}
