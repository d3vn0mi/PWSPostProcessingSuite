function Invoke-SSHConfigAnalyzer {
    <#
    .SYNOPSIS
        Analyzes SSH server configuration for security issues.
    .DESCRIPTION
        Examines /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/* for insecure
        settings including root login, password authentication, empty passwords,
        X11 forwarding, legacy protocols, and combined agent forwarding with root login.
    .PARAMETER EvidencePath
        Root folder path containing collected Linux artifacts.
    .PARAMETER Rules
        Hashtable of detection rules from the rules engine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EvidencePath,

        [Parameter(Mandatory)]
        [hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerCategory = 'SSH Configuration'
    $mitreSSH = 'T1021.004'

    # ----------------------------------------------------------------
    # Collect all sshd_config content
    # ----------------------------------------------------------------
    $configFiles = [System.Collections.Generic.List[hashtable]]::new()

    # Main config
    $mainConfigPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/ssh/sshd_config'
    if (Test-Path $mainConfigPath -PathType Leaf) {
        $configFiles.Add(@{
            Path      = $mainConfigPath
            LinuxPath = '/etc/ssh/sshd_config'
            Lines     = @(Read-ArtifactContent -Path $mainConfigPath)
        })
    }

    # sshd_config.d/ drop-in files
    $configDFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath 'etc/ssh/sshd_config.d'
    foreach ($file in $configDFiles) {
        $configFiles.Add(@{
            Path      = $file.FullName
            LinuxPath = "/etc/ssh/sshd_config.d/$($file.Name)"
            Lines     = @(Read-ArtifactContent -Path $file.FullName)
        })
    }

    if ($configFiles.Count -eq 0) {
        Write-Verbose "SSHConfigAnalyzer: No sshd_config files found, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Parse all config files into a unified settings map
    # SSH config format: "Key Value" (first occurrence wins outside Match blocks)
    # Track source file and line for evidence
    # ----------------------------------------------------------------
    $globalSettings = @{}       # key -> @{ Value; Source; Line }
    $matchBlocks = [System.Collections.Generic.List[hashtable]]::new()
    $allParsedLines = [System.Collections.Generic.List[string]]::new()

    foreach ($configFile in $configFiles) {
        $inMatchBlock = $false
        $currentMatchContext = ''
        $matchSettings = @{}

        foreach ($rawLine in $configFile.Lines) {
            $line = $rawLine.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }

            $allParsedLines.Add("[$($configFile.LinuxPath)] $line")

            # Detect Match blocks
            if ($line -match '^\s*Match\s+(.+)$') {
                # Save previous match block if any
                if ($inMatchBlock -and $matchSettings.Count -gt 0) {
                    $matchBlocks.Add(@{
                        Context  = $currentMatchContext
                        Settings = $matchSettings
                        Source   = $configFile.LinuxPath
                    })
                }
                $inMatchBlock = $true
                $currentMatchContext = $Matches[1]
                $matchSettings = @{}
                continue
            }

            # Parse "Key Value" format
            $parts = $line -split '\s+', 2
            if ($parts.Count -lt 2) { continue }

            $key = $parts[0]
            $value = $parts[1]

            if ($inMatchBlock) {
                $matchSettings[$key] = @{
                    Value  = $value
                    Source = $configFile.LinuxPath
                    Line   = $line
                }
            }
            else {
                # Global setting - first occurrence wins (SSH behavior)
                if (-not $globalSettings.ContainsKey($key)) {
                    $globalSettings[$key] = @{
                        Value  = $value
                        Source = $configFile.LinuxPath
                        Line   = $line
                    }
                }
            }
        }

        # Save last match block
        if ($inMatchBlock -and $matchSettings.Count -gt 0) {
            $matchBlocks.Add(@{
                Context  = $currentMatchContext
                Settings = $matchSettings
                Source   = $configFile.LinuxPath
            })
        }
    }

    # Helper to get a global setting value (case-insensitive key lookup)
    $getSettingValue = {
        param([string]$Key)
        foreach ($k in $globalSettings.Keys) {
            if ($k -ieq $Key) {
                return $globalSettings[$k]
            }
        }
        return $null
    }

    # ----------------------------------------------------------------
    # SSH-001 (Critical): PermitRootLogin yes
    # CIS Benchmark 5.2.10: "Ensure SSH root login is disabled"
    # ----------------------------------------------------------------
    $permitRootLogin = & $getSettingValue 'PermitRootLogin'
    if ($null -ne $permitRootLogin -and $permitRootLogin.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-001' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title 'Root login permitted via SSH' `
            -Description "PermitRootLogin is set to 'yes' in $($permitRootLogin.Source), allowing direct root authentication over SSH. Per CIS Benchmark 5.2.10, root login should be disabled to enforce accountability (all administrators must authenticate as themselves first, then escalate via sudo) and to eliminate the root account as a brute-force target." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $permitRootLogin.Source })[0].Path) `
            -Evidence @($permitRootLogin.Line) `
            -Recommendation "Set PermitRootLogin to 'no' or 'prohibit-password' per CIS 5.2.10. Use named accounts with sudo for privilege escalation to maintain an audit trail." `
            -MITRE $mitreSSH `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Direct root SSH access eliminates accountability (no individual user attribution), makes the root account a brute-force target, and bypasses sudo audit logging.'
        ))
    }

    # Also check Match blocks for PermitRootLogin
    foreach ($mb in $matchBlocks) {
        foreach ($k in $mb.Settings.Keys) {
            if ($k -ieq 'PermitRootLogin' -and $mb.Settings[$k].Value -ieq 'yes') {
                $findings.Add((New-Finding `
                    -Id 'SSH-001' `
                    -Severity 'Critical' `
                    -Category $analyzerCategory `
                    -Title "Root login permitted in Match block ($($mb.Context))" `
                    -Description "PermitRootLogin is set to 'yes' within a Match block (Match $($mb.Context)) in $($mb.Source)." `
                    -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $mb.Source })[0].Path) `
                    -Evidence @("Match $($mb.Context)", $mb.Settings[$k].Line) `
                    -Recommendation "Set PermitRootLogin to 'no' or 'prohibit-password' even within Match blocks." `
                    -MITRE $mitreSSH `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'Allows direct root login via SSH for matching conditions, enabling full system compromise if credentials are obtained.'
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # SSH-002 (High): PasswordAuthentication yes
    # CIS Benchmark 5.2.15: "Ensure only strong Key Exchange algorithms are used"
    # ----------------------------------------------------------------
    $passwordAuth = & $getSettingValue 'PasswordAuthentication'
    if ($null -ne $passwordAuth -and $passwordAuth.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-002' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title 'Password authentication enabled for SSH' `
            -Description "PasswordAuthentication is set to 'yes' in $($passwordAuth.Source). Password-based authentication is susceptible to brute-force, credential stuffing, and password spraying attacks. CIS recommends key-based authentication which provides cryptographic proof of identity and cannot be brute-forced remotely." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $passwordAuth.Source })[0].Path) `
            -Evidence @($passwordAuth.Line) `
            -Recommendation 'Disable password authentication and use key-based authentication: PasswordAuthentication no. Ensure all users have SSH keys configured before disabling.' `
            -MITRE $mitreSSH `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Password-based SSH authentication is susceptible to brute-force, credential stuffing, and password spraying attacks, potentially granting remote shell access to the system.'
        ))
    }

    # ----------------------------------------------------------------
    # SSH-003 (Critical): PermitEmptyPasswords yes
    # CIS Benchmark 5.2.9: "Ensure SSH PermitEmptyPasswords is disabled"
    # ----------------------------------------------------------------
    $permitEmpty = & $getSettingValue 'PermitEmptyPasswords'
    if ($null -ne $permitEmpty -and $permitEmpty.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-003' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title 'Empty passwords permitted for SSH' `
            -Description "PermitEmptyPasswords is set to 'yes' in $($permitEmpty.Source). Per CIS Benchmark 5.2.9, this must be disabled. Any account with an empty password field in /etc/shadow can be accessed remotely without any credentials, effectively providing unauthenticated remote shell access." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $permitEmpty.Source })[0].Path) `
            -Evidence @($permitEmpty.Line) `
            -Recommendation "Set PermitEmptyPasswords to 'no' per CIS 5.2.9. Also audit /etc/shadow for any accounts with empty password fields." `
            -MITRE $mitreSSH `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Accounts with empty passwords can be accessed remotely via SSH without any credentials. Combined with user enumeration, this provides trivial unauthenticated remote code execution.'
        ))
    }

    # ----------------------------------------------------------------
    # SSH-004 (Medium): X11Forwarding yes
    # CIS Benchmark 5.2.6: "Ensure SSH X11 forwarding is disabled"
    # ----------------------------------------------------------------
    $x11Forwarding = & $getSettingValue 'X11Forwarding'
    if ($null -ne $x11Forwarding -and $x11Forwarding.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-004' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title 'X11 forwarding enabled' `
            -Description "X11Forwarding is set to 'yes' in $($x11Forwarding.Source). Per CIS Benchmark 5.2.6, X11 forwarding should be disabled on servers. The X11 protocol was not designed with security in mind and forwarding it over SSH exposes the X11 display to hijacking by other users on the server, enabling keylogging and screenshot capture." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $x11Forwarding.Source })[0].Path) `
            -Evidence @($x11Forwarding.Line) `
            -Recommendation 'Disable X11Forwarding per CIS 5.2.6: X11Forwarding no. If GUI access is needed, use VNC over SSH tunnel instead.' `
            -MITRE $mitreSSH `
            -CVSSv3Score '4.3' `
            -TechnicalImpact 'X11 forwarding can be exploited for display hijacking, keylogging, and screenshot capture of user sessions on the server.'
        ))
    }

    # ----------------------------------------------------------------
    # SSH-005 (High): Protocol 1
    # CIS Benchmark 5.2.4: "Ensure SSH Protocol is set to 2"
    # ----------------------------------------------------------------
    $protocol = & $getSettingValue 'Protocol'
    if ($null -ne $protocol) {
        # Protocol could be "1", "1,2", or "2,1" - any inclusion of 1 is bad
        if ($protocol.Value -match '\b1\b') {
            $findings.Add((New-Finding `
                -Id 'SSH-005' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title 'SSHv1 protocol enabled' `
                -Description "SSH Protocol version 1 is enabled in $($protocol.Source). Per CIS Benchmark 5.2.4, only Protocol 2 should be used. SSHv1 has known cryptographic weaknesses including CRC-32 compensation attack and weak MAC algorithms that enable session hijacking, man-in-the-middle attacks, and traffic decryption." `
                -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $protocol.Source })[0].Path) `
                -Evidence @($protocol.Line) `
                -Recommendation 'Use only Protocol 2 per CIS 5.2.4: Protocol 2. SSHv1 has been deprecated since 2006.' `
                -MITRE $mitreSSH `
                -CVSSv3Score '7.4' `
                -TechnicalImpact 'SSHv1 has known cryptographic weaknesses that allow session hijacking, man-in-the-middle attacks, and potential traffic decryption.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # SSH-006 (Informational): Non-standard SSH port
    # ----------------------------------------------------------------
    $port = & $getSettingValue 'Port'
    if ($null -ne $port -and $port.Value -ne '22') {
        $findings.Add((New-Finding `
            -Id 'SSH-006' `
            -Severity 'Informational' `
            -Category $analyzerCategory `
            -Title "Non-standard SSH port: $($port.Value)" `
            -Description "SSH is configured to listen on port $($port.Value) instead of the default port 22 in $($port.Source). This may be intentional security hardening or an attempt to hide the SSH service." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $port.Source })[0].Path) `
            -Evidence @($port.Line) `
            -Recommendation 'Verify this is an intentional configuration. Non-standard ports provide minimal security benefit but should be documented.' `
            -MITRE $mitreSSH `
            -CVSSv3Score '' `
            -TechnicalImpact ''
        ))
    }

    # ----------------------------------------------------------------
    # SSH-007 (Medium): MaxAuthTries > 4
    # CIS Benchmark 5.2.7: "Ensure SSH MaxAuthTries is set to 4 or less"
    # ----------------------------------------------------------------
    $maxAuthTries = & $getSettingValue 'MaxAuthTries'
    if ($null -ne $maxAuthTries) {
        $maxAuthVal = 0
        if ([int]::TryParse($maxAuthTries.Value, [ref]$maxAuthVal)) {
            if ($maxAuthVal -gt 4) {
                $findings.Add((New-Finding `
                    -Id 'SSH-007' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "SSH MaxAuthTries set too high: $maxAuthVal" `
                    -Description "MaxAuthTries is set to $maxAuthVal in $($maxAuthTries.Source). Per CIS Benchmark 5.2.7, this should be 4 or less. Each SSH connection allows up to MaxAuthTries password attempts before disconnecting. A value of $maxAuthVal allows an attacker to attempt $([math]::Floor($maxAuthVal / 2)) password guesses per connection (SSH logs a failure at the halfway point), significantly increasing brute-force efficiency." `
                    -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $maxAuthTries.Source })[0].Path) `
                    -Evidence @($maxAuthTries.Line) `
                    -Recommendation 'Set MaxAuthTries to 4 or less per CIS 5.2.7 to limit brute-force attempts per connection. Combine with fail2ban for IP-based blocking.' `
                    -MITRE $mitreSSH `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact "MaxAuthTries of $maxAuthVal allows up to $([math]::Floor($maxAuthVal / 2)) password guesses per SSH connection, increasing the efficiency of brute-force attacks."
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # SSH-008 (High): AllowAgentForwarding yes + PermitRootLogin yes
    # ----------------------------------------------------------------
    $agentForwarding = & $getSettingValue 'AllowAgentForwarding'
    $agentFwdEnabled = ($null -ne $agentForwarding -and $agentForwarding.Value -ieq 'yes')
    $rootLoginEnabled = ($null -ne $permitRootLogin -and $permitRootLogin.Value -ieq 'yes')

    if ($agentFwdEnabled -and $rootLoginEnabled) {
        $evidence = [System.Collections.Generic.List[string]]::new()
        $evidence.Add($agentForwarding.Line)
        $evidence.Add($permitRootLogin.Line)

        $findings.Add((New-Finding `
            -Id 'SSH-008' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title 'Agent forwarding with root login creates hijack risk' `
            -Description "Both AllowAgentForwarding and PermitRootLogin are set to 'yes'. An attacker with root access can hijack forwarded SSH agent sockets to authenticate to other systems." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $agentForwarding.Source })[0].Path) `
            -Evidence @($evidence) `
            -Recommendation "Disable AllowAgentForwarding (set to 'no') or disable PermitRootLogin. Agent forwarding with root login allows SSH agent socket hijacking." `
            -MITRE $mitreSSH `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'An attacker with root access can hijack forwarded SSH agent sockets to authenticate to other systems, enabling lateral movement across the network.'
        ))
    }

    # ----------------------------------------------------------------
    # SSH-009 (Medium): UsePAM no — bypasses PAM security controls
    # ----------------------------------------------------------------
    $usePAM = & $getSettingValue 'UsePAM'
    if ($null -ne $usePAM -and $usePAM.Value -ieq 'no') {
        $findings.Add((New-Finding `
            -Id 'SSH-009' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title 'PAM authentication disabled for SSH (UsePAM=no)' `
            -Description "UsePAM is set to 'no' in $($usePAM.Source). This disables PAM session setup, account management, and password policies for SSH connections." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $usePAM.Source })[0].Path) `
            -Evidence @($usePAM.Line) `
            -Recommendation "Set UsePAM to 'yes' to leverage PAM security controls including account lockout, password policies, and session management." `
            -MITRE $mitreSSH `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Disabling PAM bypasses account lockout policies, password complexity requirements, and session management controls.'
        ))
    }

    # ----------------------------------------------------------------
    # SSH-010 (Medium): GatewayPorts yes — port forwarding risk
    # ----------------------------------------------------------------
    $gatewayPorts = & $getSettingValue 'GatewayPorts'
    if ($null -ne $gatewayPorts -and $gatewayPorts.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-010' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title 'SSH GatewayPorts enabled' `
            -Description "GatewayPorts is set to 'yes' in $($gatewayPorts.Source). Remote port forwards will listen on all interfaces, not just localhost." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $gatewayPorts.Source })[0].Path) `
            -Evidence @($gatewayPorts.Line) `
            -Recommendation "Set GatewayPorts to 'no' or 'clientspecified' to prevent forwarded ports from listening on external interfaces." `
            -MITRE $mitreSSH `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'GatewayPorts allows SSH tunnels to bind on all interfaces, potentially exposing internal services to external networks.'
        ))
    }

    # ----------------------------------------------------------------
    # SSH-011 (Medium): AllowTcpForwarding with PermitRootLogin
    # ----------------------------------------------------------------
    $tcpForwarding = & $getSettingValue 'AllowTcpForwarding'
    $tcpFwdEnabled = ($null -eq $tcpForwarding -or $tcpForwarding.Value -ieq 'yes')  # default is yes
    $rootLoginEnabled2 = ($null -ne $permitRootLogin -and $permitRootLogin.Value -ieq 'yes')

    if ($tcpFwdEnabled -and $rootLoginEnabled2) {
        $evidence = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $tcpForwarding) { $evidence.Add($tcpForwarding.Line) }
        else { $evidence.Add("AllowTcpForwarding: yes (default)") }
        $evidence.Add($permitRootLogin.Line)

        $findings.Add((New-Finding `
            -Id 'SSH-011' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title 'TCP forwarding enabled with root login permitted' `
            -Description "Both AllowTcpForwarding and PermitRootLogin are enabled. An attacker with root SSH access can create tunnels to internal services." `
            -ArtifactPath ($configFiles[0].Path) `
            -Evidence @($evidence) `
            -Recommendation "Disable either AllowTcpForwarding or PermitRootLogin. Use restricted shells or ForceCommand to limit forwarding." `
            -MITRE $mitreSSH `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'TCP forwarding with root login allows creating network tunnels to reach internal services, enabling lateral movement and pivoting.'
        ))
    }

    # ----------------------------------------------------------------
    # Informational summary: Match blocks detected
    # ----------------------------------------------------------------
    if ($matchBlocks.Count -gt 0) {
        $matchEvidence = [System.Collections.Generic.List[string]]::new()
        foreach ($mb in $matchBlocks) {
            $settingsList = ($mb.Settings.Keys | ForEach-Object { "$_ $($mb.Settings[$_].Value)" }) -join '; '
            $matchEvidence.Add("Match $($mb.Context) [$($mb.Source)]: $settingsList")
        }

        $findings.Add((New-Finding `
            -Id 'SSH-006' `
            -Severity 'Informational' `
            -Category $analyzerCategory `
            -Title "SSH Match blocks detected ($($matchBlocks.Count) blocks)" `
            -Description "Match blocks override global settings for specific conditions. Settings within Match blocks may weaken security for certain users, groups, or networks." `
            -ArtifactPath ($configFiles[0].Path) `
            -Evidence @($matchEvidence) `
            -Recommendation 'Review all Match blocks to ensure they do not weaken the global security posture.' `
            -MITRE $mitreSSH `
            -CVSSv3Score '' `
            -TechnicalImpact ''
        ))
    }

    return $findings.ToArray()
}
