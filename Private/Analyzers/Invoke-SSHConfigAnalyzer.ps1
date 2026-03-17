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
    # ----------------------------------------------------------------
    $permitRootLogin = & $getSettingValue 'PermitRootLogin'
    if ($null -ne $permitRootLogin -and $permitRootLogin.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-001' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title 'Root login permitted via SSH' `
            -Description "PermitRootLogin is set to 'yes' in $($permitRootLogin.Source), allowing direct root authentication over SSH." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $permitRootLogin.Source })[0].Path) `
            -Evidence @($permitRootLogin.Line) `
            -Recommendation "Set PermitRootLogin to 'no' or 'prohibit-password'. Use regular accounts and sudo for privilege escalation." `
            -MITRE $mitreSSH
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
                    -MITRE $mitreSSH
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # SSH-002 (High): PasswordAuthentication yes
    # ----------------------------------------------------------------
    $passwordAuth = & $getSettingValue 'PasswordAuthentication'
    if ($null -ne $passwordAuth -and $passwordAuth.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-002' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title 'Password authentication enabled for SSH' `
            -Description "PasswordAuthentication is set to 'yes' in $($passwordAuth.Source). Password-based auth is susceptible to brute-force attacks." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $passwordAuth.Source })[0].Path) `
            -Evidence @($passwordAuth.Line) `
            -Recommendation 'Disable password authentication and use key-based authentication: PasswordAuthentication no' `
            -MITRE $mitreSSH
        ))
    }

    # ----------------------------------------------------------------
    # SSH-003 (High): PermitEmptyPasswords yes
    # ----------------------------------------------------------------
    $permitEmpty = & $getSettingValue 'PermitEmptyPasswords'
    if ($null -ne $permitEmpty -and $permitEmpty.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-003' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title 'Empty passwords permitted for SSH' `
            -Description "PermitEmptyPasswords is set to 'yes' in $($permitEmpty.Source). Accounts with empty passwords can authenticate via SSH." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $permitEmpty.Source })[0].Path) `
            -Evidence @($permitEmpty.Line) `
            -Recommendation "Set PermitEmptyPasswords to 'no'." `
            -MITRE $mitreSSH
        ))
    }

    # ----------------------------------------------------------------
    # SSH-004 (Medium): X11Forwarding yes
    # ----------------------------------------------------------------
    $x11Forwarding = & $getSettingValue 'X11Forwarding'
    if ($null -ne $x11Forwarding -and $x11Forwarding.Value -ieq 'yes') {
        $findings.Add((New-Finding `
            -Id 'SSH-004' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title 'X11 forwarding enabled' `
            -Description "X11Forwarding is set to 'yes' in $($x11Forwarding.Source). X11 forwarding can be exploited for display hijacking and keylogging." `
            -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $x11Forwarding.Source })[0].Path) `
            -Evidence @($x11Forwarding.Line) `
            -Recommendation 'Disable X11Forwarding unless explicitly required: X11Forwarding no' `
            -MITRE $mitreSSH
        ))
    }

    # ----------------------------------------------------------------
    # SSH-005 (Medium): Protocol 1
    # ----------------------------------------------------------------
    $protocol = & $getSettingValue 'Protocol'
    if ($null -ne $protocol) {
        # Protocol could be "1", "1,2", or "2,1" - any inclusion of 1 is bad
        if ($protocol.Value -match '\b1\b') {
            $findings.Add((New-Finding `
                -Id 'SSH-005' `
                -Severity 'Medium' `
                -Category $analyzerCategory `
                -Title 'SSHv1 protocol enabled' `
                -Description "SSH Protocol version 1 is enabled in $($protocol.Source). SSHv1 has known cryptographic weaknesses and is deprecated." `
                -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $protocol.Source })[0].Path) `
                -Evidence @($protocol.Line) `
                -Recommendation 'Use only Protocol 2: Protocol 2' `
                -MITRE $mitreSSH
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
            -MITRE $mitreSSH
        ))
    }

    # ----------------------------------------------------------------
    # SSH-007 (Medium): MaxAuthTries > 6
    # ----------------------------------------------------------------
    $maxAuthTries = & $getSettingValue 'MaxAuthTries'
    if ($null -ne $maxAuthTries) {
        $maxAuthVal = 0
        if ([int]::TryParse($maxAuthTries.Value, [ref]$maxAuthVal)) {
            if ($maxAuthVal -gt 6) {
                $findings.Add((New-Finding `
                    -Id 'SSH-007' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "SSH MaxAuthTries set too high: $maxAuthVal" `
                    -Description "MaxAuthTries is set to $maxAuthVal in $($maxAuthTries.Source). High values allow more brute-force attempts per connection." `
                    -ArtifactPath (($configFiles | Where-Object { $_.LinuxPath -eq $maxAuthTries.Source })[0].Path) `
                    -Evidence @($maxAuthTries.Line) `
                    -Recommendation 'Set MaxAuthTries to 3-6 to limit authentication attempts per connection.' `
                    -MITRE $mitreSSH
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
            -MITRE $mitreSSH
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
            -MITRE $mitreSSH
        ))
    }

    return $findings.ToArray()
}
