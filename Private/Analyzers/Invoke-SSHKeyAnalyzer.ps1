function Invoke-SSHKeyAnalyzer {
    <#
    .SYNOPSIS
        Analyzes SSH keys, authorized_keys, known_hosts, and SSH client configs.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Find all user home directories
    $homePath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/home'
    $rootPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/root'

    $userDirs = @()
    if (Test-Path $homePath -PathType Container) {
        $userDirs += Get-ChildItem -Path $homePath -Directory -ErrorAction SilentlyContinue
    }
    if (Test-Path $rootPath -PathType Container) {
        $userDirs += Get-Item $rootPath
    }

    $totalKeys = 0
    $totalKnownHosts = 0

    foreach ($userDir in $userDirs) {
        $userName = $userDir.Name
        $sshDir = Join-Path $userDir.FullName '.ssh'

        if (-not (Test-Path $sshDir -PathType Container)) { continue }

        # Check authorized_keys
        $authKeysPath = Join-Path $sshDir 'authorized_keys'
        if (Test-Path $authKeysPath) {
            $authKeys = Read-ArtifactContent -Path $authKeysPath
            $keyCount = @($authKeys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.StartsWith('#') }).Count
            $totalKeys += $keyCount

            if ($keyCount -gt 0) {
                # Check for command= restrictions (potential backdoor)
                $commandKeys = $authKeys | Where-Object { $_ -match '^command=' }
                if ($commandKeys) {
                    foreach ($cmdKey in $commandKeys) {
                        $findings.Add((New-Finding -Id "SSHKEY-001" -Severity "Medium" -Category "SSH Keys" `
                            -Title "SSH key with command= restriction for $userName" `
                            -Description "An SSH authorized key has a command= option, which forces execution of a specific command on login. This can be legitimate but also used as a backdoor." `
                            -ArtifactPath "/home/$userName/.ssh/authorized_keys" `
                            -Evidence @($cmdKey.Substring(0, [Math]::Min($cmdKey.Length, 200))) `
                            -Recommendation "Verify the forced command is expected and legitimate" `
                            -MITRE "T1098.004" `
                            -CVSSv3Score "6.5" `
                            -TechnicalImpact "Forced command keys can be used as a backdoor to execute attacker-controlled commands on every SSH login."))
                    }
                }

                # Check for keys with no-* options (no-pty, no-port-forwarding etc - could be restrictive or hiding)
                $restrictedKeys = $authKeys | Where-Object { $_ -match '^(no-pty|no-port-forwarding|no-agent-forwarding|no-X11-forwarding)' }

                # Check for from= restrictions (could limit or could indicate targeted access)
                $fromKeys = $authKeys | Where-Object { $_ -match '^from=' }
                if ($fromKeys) {
                    $findings.Add((New-Finding -Id "SSHKEY-002" -Severity "Informational" -Category "SSH Keys" `
                        -Title "SSH key with source IP restriction for $userName" `
                        -Description "One or more SSH keys have from= restrictions limiting which IPs can use them." `
                        -ArtifactPath "/home/$userName/.ssh/authorized_keys" `
                        -Evidence @($fromKeys | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 150)) }) `
                        -Recommendation "Review allowed source IPs for legitimacy" `
                        -CVSSv3Score '' `
                        -TechnicalImpact ''))
                }

                # Report all authorized keys found (High for root)
                $severity = if ($userName -eq 'root') { 'Medium' } else { 'Informational' }
                $sshkey003CVSSv3Score = if ($userName -eq 'root') { '6.5' } else { '' }
                $sshkey003TechnicalImpact = if ($userName -eq 'root') { 'Authorized SSH keys for root grant passwordless remote root access, enabling full system control if any key is compromised.' } else { '' }
                $findings.Add((New-Finding -Id "SSHKEY-003" -Severity $severity -Category "SSH Keys" `
                    -Title "Authorized SSH keys found for $userName ($keyCount keys)" `
                    -Description "$keyCount SSH public keys are authorized for $userName. Each key grants passwordless SSH access." `
                    -ArtifactPath "/home/$userName/.ssh/authorized_keys" `
                    -Evidence @($authKeys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
                        # Show just the key type and comment (last field)
                        $parts = $_ -split '\s+'
                        $keyType = if ($parts.Count -ge 2) { $parts[0] } else { 'unknown' }
                        $comment = if ($parts.Count -ge 3) { $parts[-1] } else { 'no-comment' }
                        "$keyType ... $comment"
                    }) `
                    -Recommendation "Verify all authorized keys belong to legitimate users" `
                    -CVSSv3Score $sshkey003CVSSv3Score `
                    -TechnicalImpact $sshkey003TechnicalImpact))
            }
        }

        # Check known_hosts
        $knownHostsPath = Join-Path $sshDir 'known_hosts'
        if (Test-Path $knownHostsPath) {
            $knownHosts = Read-ArtifactContent -Path $knownHostsPath
            $hostCount = @($knownHosts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
            $totalKnownHosts += $hostCount

            # Check for .onion hosts (Tor)
            $onionHosts = $knownHosts | Where-Object { $_ -match '\.onion' }
            if ($onionHosts) {
                $findings.Add((New-Finding -Id "SSHKEY-004" -Severity "High" -Category "SSH Keys" `
                    -Title "SSH connections to Tor .onion addresses by $userName" `
                    -Description "The known_hosts file contains Tor hidden service addresses, indicating SSH connections through Tor." `
                    -ArtifactPath "/home/$userName/.ssh/known_hosts" `
                    -Evidence @($onionHosts | Select-Object -First 5) `
                    -Recommendation "Investigate why Tor hidden services were accessed via SSH" `
                    -MITRE "T1090.003" `
                    -CVSSv3Score "7.5" `
                    -TechnicalImpact "SSH connections through Tor indicate covert communication channels, potentially used for data exfiltration or C2 traffic evasion."))
            }

            # Extract unique host IPs/names for analysis
            $hosts = $knownHosts | ForEach-Object {
                $hostField = ($_ -split '\s+')[0]
                $hostField -split ','
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

            if ($hostCount -gt 0) {
                $findings.Add((New-Finding -Id "SSHKEY-005" -Severity "Informational" -Category "SSH Keys" `
                    -Title "SSH known hosts for $userName ($hostCount entries)" `
                    -Description "$userName has connected to $hostCount SSH hosts." `
                    -ArtifactPath "/home/$userName/.ssh/known_hosts" `
                    -Evidence @($hosts | Select-Object -First 20) `
                    -Recommendation "Review connected hosts for unauthorized lateral movement" `
                    -CVSSv3Score '' `
                    -TechnicalImpact ''))
            }
        }

        # Check SSH client config
        $sshConfigPath = Join-Path $sshDir 'config'
        if (Test-Path $sshConfigPath) {
            $sshConfig = Read-ArtifactContent -Path $sshConfigPath
            $content = $sshConfig -join "`n"

            # Check for ProxyCommand (can be used for tunneling)
            if ($content -match 'ProxyCommand') {
                $proxyLines = $sshConfig | Where-Object { $_ -match 'ProxyCommand' }
                $findings.Add((New-Finding -Id "SSHKEY-006" -Severity "Medium" -Category "SSH Keys" `
                    -Title "SSH ProxyCommand configured for $userName" `
                    -Description "SSH client config has ProxyCommand entries which can be used for tunneling and pivoting." `
                    -ArtifactPath "/home/$userName/.ssh/config" `
                    -Evidence @($proxyLines) `
                    -Recommendation "Verify ProxyCommand entries are for legitimate use" `
                    -MITRE "T1090.001" `
                    -CVSSv3Score "5.3" `
                    -TechnicalImpact "ProxyCommand entries can be used for network tunneling and pivoting to access otherwise unreachable internal systems."))
            }

            # Check for StrictHostKeyChecking no (MITM risk)
            if ($content -match 'StrictHostKeyChecking\s+no') {
                $findings.Add((New-Finding -Id "SSHKEY-007" -Severity "Medium" -Category "SSH Keys" `
                    -Title "SSH host key checking disabled for $userName" `
                    -Description "StrictHostKeyChecking is set to no, disabling MITM protection for SSH connections." `
                    -ArtifactPath "/home/$userName/.ssh/config" `
                    -Evidence @("StrictHostKeyChecking no") `
                    -Recommendation "Set StrictHostKeyChecking to yes or ask" `
                    -MITRE "T1557" `
                    -CVSSv3Score "5.9" `
                    -TechnicalImpact "Disabling host key checking allows man-in-the-middle attacks on SSH connections, enabling credential interception and session hijacking."))
            }
        }

        # Check for private keys (existence)
        $privateKeyFiles = Get-ChildItem -Path $sshDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^id_(rsa|dsa|ecdsa|ed25519)$' -or $_.Name -match '\.pem$' }
        if ($privateKeyFiles) {
            $findings.Add((New-Finding -Id "SSHKEY-008" -Severity "Informational" -Category "SSH Keys" `
                -Title "SSH private keys found for $userName" `
                -Description "SSH private key files found in $userName's .ssh directory." `
                -ArtifactPath "/home/$userName/.ssh/" `
                -Evidence @($privateKeyFiles.Name) `
                -Recommendation "Ensure private keys are password-protected and not shared" `
                -CVSSv3Score '' `
                -TechnicalImpact ''))
        }
    }

    return $findings.ToArray()
}
