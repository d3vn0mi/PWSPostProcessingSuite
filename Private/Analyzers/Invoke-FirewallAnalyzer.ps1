function Invoke-FirewallAnalyzer {
    <#
    .SYNOPSIS
        Analyzes firewall configurations (iptables, nftables, ufw).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $firewallFound = $false

    # Check iptables save/rules
    $iptablesPaths = @(
        '/etc/iptables/rules.v4'
        '/etc/iptables/rules.v6'
        '/etc/sysconfig/iptables'
        '/etc/iptables.rules'
    )

    foreach ($rulePath in $iptablesPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $rulePath
        if (-not (Test-Path $resolved)) { continue }

        $firewallFound = $true
        $lines = Read-ArtifactContent -Path $resolved
        $acceptAll = @()
        $hasDropPolicy = $false

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            # Check default policy
            if ($trimmed -match ':INPUT\s+(ACCEPT|DROP|REJECT)') {
                if ($Matches[1] -eq 'ACCEPT') {
                    $findings.Add((New-Finding -Id "FW-001" -Severity "High" -Category "Firewall" `
                        -Title "Default INPUT policy is ACCEPT" `
                        -Description "The default INPUT chain policy accepts all traffic. This means any traffic not explicitly denied will be allowed." `
                        -ArtifactPath $rulePath `
                        -Evidence @($trimmed) `
                        -Recommendation "Set default INPUT policy to DROP and explicitly allow needed traffic" `
                        -MITRE "T1562.004" `
                        -CVSSv3Score '7.5' `
                        -TechnicalImpact "Allows unrestricted inbound network access to all services, exposing the system to remote exploitation of any listening service"))
                }
                else {
                    $hasDropPolicy = $true
                }
            }

            if ($trimmed -match ':FORWARD\s+ACCEPT') {
                $findings.Add((New-Finding -Id "FW-002" -Severity "Medium" -Category "Firewall" `
                    -Title "Default FORWARD policy is ACCEPT" `
                    -Description "The default FORWARD chain policy accepts all traffic, allowing the system to route traffic between interfaces." `
                    -ArtifactPath $rulePath `
                    -Evidence @($trimmed) `
                    -Recommendation "Set default FORWARD policy to DROP unless this is a router/gateway" `
                    -MITRE "T1090" `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact "Enables the system to be used as a network pivot point, allowing lateral movement between network segments"))
            }

            # Check for overly permissive rules
            if ($trimmed -match '-A\s+INPUT.*-j\s+ACCEPT' -and $trimmed -notmatch '-s\s+' -and $trimmed -notmatch '--dport\s+' -and $trimmed -notmatch '-p\s+(tcp|udp|icmp)') {
                $acceptAll += $trimmed
            }

            # Check for known bad ports being allowed
            $knownBadPorts = @('4444', '5555', '1337', '31337', '6666', '6667', '9001')
            foreach ($port in $knownBadPorts) {
                if ($trimmed -match "--dport\s+$port\s+" -and $trimmed -match '-j\s+ACCEPT') {
                    $findings.Add((New-Finding -Id "FW-003" -Severity "High" -Category "Firewall" `
                        -Title "Suspicious port $port allowed in firewall" `
                        -Description "Firewall rule allows traffic on port $port, commonly associated with reverse shells or C2 frameworks." `
                        -ArtifactPath $rulePath `
                        -Evidence @($trimmed) `
                        -Recommendation "Investigate why port $port is allowed and remove if not needed" `
                        -MITRE "T1571" `
                        -CVSSv3Score '8.1' `
                        -TechnicalImpact "Firewall rule permits traffic on a port commonly used by reverse shells or C2 frameworks, potentially enabling remote attacker access"))
                }
            }
        }

        if ($acceptAll.Count -gt 0) {
            $findings.Add((New-Finding -Id "FW-004" -Severity "Medium" -Category "Firewall" `
                -Title "Overly permissive firewall rules" `
                -Description "Found $($acceptAll.Count) rules that accept traffic without specifying source, port, or protocol restrictions." `
                -ArtifactPath $rulePath `
                -Evidence @($acceptAll | Select-Object -First 5) `
                -Recommendation "Restrict firewall rules to specific ports and source addresses" `
                -MITRE "T1562.004" `
                -CVSSv3Score '5.3' `
                -TechnicalImpact "Overly broad firewall rules reduce network segmentation effectiveness, increasing attack surface for remote exploitation"))
        }
    }

    # Check UFW configuration
    $ufwPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/ufw/ufw.conf'
    if (Test-Path $ufwPath) {
        $firewallFound = $true
        $ufwContent = (Read-ArtifactContent -Path $ufwPath) -join "`n"

        if ($ufwContent -match 'ENABLED=no') {
            $findings.Add((New-Finding -Id "FW-005" -Severity "High" -Category "Firewall" `
                -Title "UFW firewall is disabled" `
                -Description "The UFW firewall is explicitly disabled in its configuration." `
                -ArtifactPath "/etc/ufw/ufw.conf" `
                -Evidence @("ENABLED=no") `
                -Recommendation "Enable UFW: ufw enable" `
                -MITRE "T1562.004" `
                -CVSSv3Score '7.5' `
                -TechnicalImpact "Host-based firewall is disabled, leaving all network services exposed to unrestricted remote access"))
        }
    }

    if (-not $firewallFound) {
        $findings.Add((New-Finding -Id "FW-006" -Severity "High" -Category "Firewall" `
            -Title "No firewall configuration found" `
            -Description "No iptables rules, nftables, or UFW configuration was found in the evidence. The system may have no firewall configured." `
            -ArtifactPath "" `
            -Evidence @("No firewall config found in standard locations") `
            -Recommendation "Configure a host-based firewall (iptables/nftables/ufw)" `
            -MITRE "T1562.004" `
            -CVSSv3Score '7.5' `
            -TechnicalImpact "Absence of host-based firewall leaves all network services exposed, allowing unrestricted remote access to any listening port"))
    }

    return $findings.ToArray()
}
