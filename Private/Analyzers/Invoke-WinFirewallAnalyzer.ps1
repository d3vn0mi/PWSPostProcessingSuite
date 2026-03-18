function Invoke-WinFirewallAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows Firewall configuration for security issues.
    .DESCRIPTION
        Examines collected Windows Firewall data including profile status, default
        actions, and individual rules. Identifies disabled profiles, permissive default
        actions, rules allowing traffic on known-bad ports, overly broad allow rules,
        and profile configuration inconsistencies.
    .PARAMETER EvidencePath
        Root folder path containing collected Windows artifacts.
    .PARAMETER Rules
        Hashtable of detection rules from the rules engine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerCategory = 'Windows Firewall'
    $mitreFirewall = 'T1562.004'

    # ----------------------------------------------------------------
    # Load artifacts
    # ----------------------------------------------------------------
    $firewallDir = Join-Path $EvidencePath 'firewall'
    $commandsDir = Join-Path $EvidencePath 'collected_commands'

    $profilesPath = Join-Path $firewallDir 'firewall_profiles.txt'
    $rulesCsvPath = Join-Path $firewallDir 'firewall_rules.csv'
    $rulesTxtPath = Join-Path $firewallDir 'firewall_rules.txt'
    $netshPath = Join-Path $commandsDir 'netsh_firewall.txt'

    # Known bad ports (commonly used by C2, reverse shells, etc.)
    $knownBadPorts = @('4444', '5555', '1337', '31337', '6666', '6667', '9001', '8443', '1234', '4321', '7777', '13337')
    if ($Rules -and $Rules.ContainsKey('suspicious_ports')) {
        $knownBadPorts += $Rules['suspicious_ports']
        $knownBadPorts = @($knownBadPorts | Select-Object -Unique)
    }

    $firewallDataFound = $false

    # ----------------------------------------------------------------
    # Parse firewall profiles
    # ----------------------------------------------------------------
    $profiles = [System.Collections.Generic.List[hashtable]]::new()
    $disabledProfiles = [System.Collections.Generic.List[string]]::new()
    $allowInboundProfiles = [System.Collections.Generic.List[string]]::new()

    if (Test-Path $profilesPath) {
        $firewallDataFound = $true
        $content = Get-Content -Path $profilesPath -ErrorAction SilentlyContinue
        $currentProfile = $null

        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($currentProfile -and $currentProfile.Name) {
                    $profiles.Add($currentProfile)
                    $currentProfile = $null
                }
                continue
            }

            # Detect profile name (e.g., "Domain Profile Settings:", "Name : Domain", or "Profile = Domain")
            if ($trimmed -match '(?i)^(Domain|Private|Public)\s+(Profile\s+Settings|Profile)\s*:?\s*$') {
                if ($currentProfile -and $currentProfile.Name) { $profiles.Add($currentProfile) }
                $currentProfile = @{
                    Name = $Matches[1]
                    Enabled = $true
                    DefaultInboundAction = 'Block'
                    DefaultOutboundAction = 'Allow'
                }
            }
            elseif ($trimmed -match '(?i)^(Name|Profile)\s*[=:]\s*(Domain|Private|Public)') {
                if ($currentProfile -and $currentProfile.Name) { $profiles.Add($currentProfile) }
                $currentProfile = @{
                    Name = $Matches[2]
                    Enabled = $true
                    DefaultInboundAction = 'Block'
                    DefaultOutboundAction = 'Allow'
                }
            }
            elseif ($currentProfile) {
                if ($trimmed -match '(?i)^(Enabled|State)\s*[=:]\s*(.+)$') {
                    $val = $Matches[2].Trim()
                    $currentProfile.Enabled = $val -match '(?i)^(true|yes|on|enabled|1)$'
                }
                elseif ($trimmed -match '(?i)^(DefaultInboundAction|Firewall Policy|Inbound)\s*[=:]\s*(.+)$') {
                    $currentProfile.DefaultInboundAction = $Matches[2].Trim()
                }
                elseif ($trimmed -match '(?i)^(DefaultOutboundAction|Outbound)\s*[=:]\s*(.+)$') {
                    $currentProfile.DefaultOutboundAction = $Matches[2].Trim()
                }
            }
        }
        if ($currentProfile -and $currentProfile.Name) { $profiles.Add($currentProfile) }
    }

    # Also try parsing netsh output as fallback for profile info
    if ($profiles.Count -eq 0 -and (Test-Path $netshPath)) {
        $firewallDataFound = $true
        $content = Get-Content -Path $netshPath -ErrorAction SilentlyContinue
        $currentProfile = $null

        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($currentProfile -and $currentProfile.Name) {
                    $profiles.Add($currentProfile)
                    $currentProfile = $null
                }
                continue
            }

            if ($trimmed -match '(?i)(Domain|Private|Public)\s+Profile\s+Settings') {
                if ($currentProfile -and $currentProfile.Name) { $profiles.Add($currentProfile) }
                $currentProfile = @{
                    Name = $Matches[1]
                    Enabled = $true
                    DefaultInboundAction = 'Block'
                    DefaultOutboundAction = 'Allow'
                }
            }
            elseif ($currentProfile) {
                if ($trimmed -match '(?i)^State\s+(.+)$') {
                    $currentProfile.Enabled = $Matches[1].Trim() -match '(?i)(ON|enabled)'
                }
                elseif ($trimmed -match '(?i)^Firewall\s+Policy\s+(.+)$') {
                    $policy = $Matches[1].Trim()
                    if ($policy -match '(?i)AllowInbound') {
                        $currentProfile.DefaultInboundAction = 'Allow'
                    }
                    elseif ($policy -match '(?i)BlockInbound') {
                        $currentProfile.DefaultInboundAction = 'Block'
                    }
                }
            }
        }
        if ($currentProfile -and $currentProfile.Name) { $profiles.Add($currentProfile) }
    }

    # ----------------------------------------------------------------
    # WFW-001: Windows Firewall is disabled (any profile)
    # ----------------------------------------------------------------
    foreach ($profile in $profiles) {
        if (-not $profile.Enabled) {
            $disabledProfiles.Add($profile.Name)
        }
    }

    if ($disabledProfiles.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WFW-001' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title "Windows Firewall disabled on $($disabledProfiles.Count) profile(s)" `
            -Description "Windows Firewall is disabled on the following profile(s): $($disabledProfiles -join ', '). A disabled firewall leaves the system exposed to all network traffic without filtering." `
            -ArtifactPath $(if (Test-Path $profilesPath) { $profilesPath } else { $netshPath }) `
            -Evidence @($disabledProfiles | ForEach-Object { "Profile: $_ - Firewall: Disabled" }) `
            -Recommendation 'Enable Windows Firewall on all profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True' `
            -MITRE $mitreFirewall `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Disabled firewall profiles expose all network services to unrestricted access, allowing direct exploitation of any listening service.'
        ))
    }

    # ----------------------------------------------------------------
    # WFW-002: Default inbound action is Allow on any profile
    # ----------------------------------------------------------------
    foreach ($profile in $profiles) {
        if ($profile.DefaultInboundAction -match '(?i)Allow') {
            $allowInboundProfiles.Add($profile.Name)
        }
    }

    if ($allowInboundProfiles.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WFW-002' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title "Default inbound action is Allow on $($allowInboundProfiles.Count) profile(s)" `
            -Description "The default inbound action is set to Allow on the following profile(s): $($allowInboundProfiles -join ', '). This means all inbound traffic is permitted unless explicitly blocked by a rule." `
            -ArtifactPath $(if (Test-Path $profilesPath) { $profilesPath } else { $netshPath }) `
            -Evidence @($allowInboundProfiles | ForEach-Object { "Profile: $_ - DefaultInboundAction: Allow" }) `
            -Recommendation 'Set default inbound action to Block on all profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block' `
            -MITRE $mitreFirewall `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Default Allow inbound policy permits all incoming connections unless explicitly denied, exposing all services to network access.'
        ))
    }

    # ----------------------------------------------------------------
    # WFW-005: Public profile less restrictive than Domain profile
    # ----------------------------------------------------------------
    $domainProfile = $profiles | Where-Object { $_.Name -eq 'Domain' } | Select-Object -First 1
    $publicProfile = $profiles | Where-Object { $_.Name -eq 'Public' } | Select-Object -First 1

    if ($domainProfile -and $publicProfile) {
        $publicLessRestrictive = $false
        $evidence = @()

        # Check if Public is enabled but Domain is disabled
        if ($publicProfile.Enabled -and -not $domainProfile.Enabled) {
            # Domain disabled is already caught by WFW-001, but note the inconsistency
        }

        # Check if Public allows inbound but Domain blocks
        if ($publicProfile.DefaultInboundAction -match '(?i)Allow' -and
            $domainProfile.DefaultInboundAction -match '(?i)Block') {
            $publicLessRestrictive = $true
            $evidence += "Public profile allows inbound by default, Domain profile blocks"
        }

        # Check if Public is disabled but Domain is enabled (Public should be MORE restrictive)
        if (-not $publicProfile.Enabled -and $domainProfile.Enabled) {
            $publicLessRestrictive = $true
            $evidence += "Public profile firewall is disabled while Domain profile is enabled"
        }

        if ($publicLessRestrictive) {
            $findings.Add((New-Finding `
                -Id 'WFW-005' `
                -Severity 'Medium' `
                -Category $analyzerCategory `
                -Title 'Public profile less restrictive than Domain profile' `
                -Description "The Public firewall profile is less restrictive than the Domain profile. The Public profile should be the most restrictive since it applies to untrusted networks." `
                -ArtifactPath $(if (Test-Path $profilesPath) { $profilesPath } else { $netshPath }) `
                -Evidence $evidence `
                -Recommendation 'Ensure the Public profile is the most restrictive. Block inbound by default and only allow specific required rules.' `
                -MITRE $mitreFirewall `
                -CVSSv3Score '5.3' `
                -TechnicalImpact 'A permissive Public profile exposes the system to attacks when connected to untrusted networks such as public Wi-Fi.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # Parse firewall rules
    # ----------------------------------------------------------------
    $firewallRules = [System.Collections.Generic.List[hashtable]]::new()

    if (Test-Path $rulesCsvPath) {
        $firewallDataFound = $true
        try {
            $csvData = Import-Csv -Path $rulesCsvPath
            foreach ($row in $csvData) {
                $rule = @{
                    Name        = if ($row.Name) { $row.Name } elseif ($row.DisplayName) { $row.DisplayName } else { '' }
                    Direction   = if ($row.Direction) { $row.Direction } else { '' }
                    Action      = if ($row.Action) { $row.Action } else { '' }
                    Protocol    = if ($row.Protocol) { $row.Protocol } else { '' }
                    LocalPort   = if ($row.LocalPort) { $row.LocalPort } else { '' }
                    RemotePort  = if ($row.RemotePort) { $row.RemotePort } else { '' }
                    Program     = if ($row.Program) { $row.Program } elseif ($row.ApplicationName) { $row.ApplicationName } else { '' }
                    Enabled     = if ($row.Enabled) { $row.Enabled -match '(?i)^(true|yes|1)$' } else { $true }
                    Profile     = if ($row.Profile) { $row.Profile } else { '' }
                    RemoteAddress = if ($row.RemoteAddress) { $row.RemoteAddress } else { '' }
                    RawLine     = ($row.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                }
                $firewallRules.Add($rule)
            }
        }
        catch {
            Write-Verbose "WinFirewallAnalyzer: Failed to parse firewall rules CSV: $_"
        }
    }
    elseif (Test-Path $rulesTxtPath) {
        $firewallDataFound = $true
        $content = Get-Content -Path $rulesTxtPath -ErrorAction SilentlyContinue
        $currentRule = $null

        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($currentRule -and $currentRule.Name) {
                    $firewallRules.Add($currentRule)
                    $currentRule = $null
                }
                continue
            }

            if ($trimmed -match '(?i)^(Name|DisplayName|Rule Name)\s*[=:]\s*(.+)$') {
                if ($currentRule -and $currentRule.Name) { $firewallRules.Add($currentRule) }
                $currentRule = @{
                    Name = $Matches[2].Trim(); Direction = ''; Action = ''; Protocol = ''
                    LocalPort = ''; RemotePort = ''; Program = ''; Enabled = $true
                    Profile = ''; RemoteAddress = ''; RawLine = $trimmed
                }
            }
            elseif ($currentRule) {
                if ($trimmed -match '(?i)^Direction\s*[=:]\s*(.+)$') {
                    $currentRule.Direction = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^Action\s*[=:]\s*(.+)$') {
                    $currentRule.Action = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^Protocol\s*[=:]\s*(.+)$') {
                    $currentRule.Protocol = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^(LocalPort|Local Port)\s*[=:]\s*(.+)$') {
                    $currentRule.LocalPort = $Matches[2].Trim()
                }
                elseif ($trimmed -match '(?i)^(RemotePort|Remote Port)\s*[=:]\s*(.+)$') {
                    $currentRule.RemotePort = $Matches[2].Trim()
                }
                elseif ($trimmed -match '(?i)^(Program|ApplicationName|Application)\s*[=:]\s*(.+)$') {
                    $currentRule.Program = $Matches[2].Trim()
                }
                elseif ($trimmed -match '(?i)^Enabled\s*[=:]\s*(.+)$') {
                    $currentRule.Enabled = $Matches[1].Trim() -match '(?i)^(true|yes|1)$'
                }
                elseif ($trimmed -match '(?i)^Profile\s*[=:]\s*(.+)$') {
                    $currentRule.Profile = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^(RemoteAddress|Remote Address)\s*[=:]\s*(.+)$') {
                    $currentRule.RemoteAddress = $Matches[2].Trim()
                }
                $currentRule.RawLine += "; $trimmed"
            }
        }
        if ($currentRule -and $currentRule.Name) { $firewallRules.Add($currentRule) }
    }

    # ----------------------------------------------------------------
    # Analyze firewall rules
    # ----------------------------------------------------------------
    $enabledAllowInbound = @($firewallRules | Where-Object {
        $_.Enabled -and $_.Action -match '(?i)Allow' -and $_.Direction -match '(?i)In'
    })

    $rulesArtifactPath = if (Test-Path $rulesCsvPath) { $rulesCsvPath }
        elseif (Test-Path $rulesTxtPath) { $rulesTxtPath }
        else { '' }

    # ----------------------------------------------------------------
    # WFW-003: Firewall rule allows traffic on known bad port
    # ----------------------------------------------------------------
    foreach ($rule in $enabledAllowInbound) {
        $localPorts = $rule.LocalPort -split '[,;]' | ForEach-Object { $_.Trim() }
        foreach ($port in $localPorts) {
            if ($port -in $knownBadPorts) {
                $findings.Add((New-Finding `
                    -Id 'WFW-003' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "Firewall allows traffic on suspicious port $port" `
                    -Description "Firewall rule '$($rule.Name)' allows inbound traffic on port $port, which is commonly associated with reverse shells, C2 frameworks, or hacking tools." `
                    -ArtifactPath $rulesArtifactPath `
                    -Evidence @("Rule: $($rule.Name)", "Direction: Inbound", "Action: Allow", "Port: $port", "Protocol: $($rule.Protocol)", "Profile: $($rule.Profile)") `
                    -Recommendation "Investigate why port $port is allowed. Remove the rule if not required for legitimate business operations." `
                    -MITRE 'T1571' `
                    -CVSSv3Score '8.1' `
                    -TechnicalImpact "Firewall rule permits traffic on port $port, commonly used by reverse shells and C2 frameworks, potentially enabling remote attacker access."
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # WFW-004: Firewall rule allows all inbound traffic (any port, any program)
    # ----------------------------------------------------------------
    $overlyPermissiveRules = [System.Collections.Generic.List[string]]::new()
    foreach ($rule in $enabledAllowInbound) {
        $isAnyPort = [string]::IsNullOrWhiteSpace($rule.LocalPort) -or $rule.LocalPort -match '(?i)^(Any|\*)$'
        $isAnyProgram = [string]::IsNullOrWhiteSpace($rule.Program) -or $rule.Program -match '(?i)^(Any|\*)$'
        $isAnyRemote = [string]::IsNullOrWhiteSpace($rule.RemoteAddress) -or $rule.RemoteAddress -match '(?i)^(Any|\*)$'

        if ($isAnyPort -and $isAnyProgram -and $isAnyRemote) {
            $overlyPermissiveRules.Add($rule.Name)
        }
    }

    if ($overlyPermissiveRules.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WFW-004' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Overly permissive firewall rules ($($overlyPermissiveRules.Count))" `
            -Description "Found $($overlyPermissiveRules.Count) firewall rule(s) that allow all inbound traffic without restricting by port, program, or remote address." `
            -ArtifactPath $rulesArtifactPath `
            -Evidence @($overlyPermissiveRules | Select-Object -First 10 | ForEach-Object { "Rule: $_" }) `
            -Recommendation 'Restrict these rules to specific ports, programs, or remote addresses. Remove rules that are not needed.' `
            -MITRE $mitreFirewall `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Overly broad firewall rules effectively negate the firewall protection, allowing unrestricted inbound access.'
        ))
    }

    # ----------------------------------------------------------------
    # WFW-006: Large number of allow rules (> 100)
    # ----------------------------------------------------------------
    if ($enabledAllowInbound.Count -gt 100) {
        $findings.Add((New-Finding `
            -Id 'WFW-006' `
            -Severity 'Low' `
            -Category $analyzerCategory `
            -Title "Large number of inbound allow rules ($($enabledAllowInbound.Count))" `
            -Description "There are $($enabledAllowInbound.Count) enabled inbound allow rules in the Windows Firewall. A large number of rules makes it difficult to audit and maintain the firewall, increasing the risk of misconfigurations." `
            -ArtifactPath $rulesArtifactPath `
            -Evidence @("Total enabled inbound allow rules: $($enabledAllowInbound.Count)", "Recommendation: Aim for fewer than 100 inbound allow rules") `
            -Recommendation 'Review and consolidate firewall rules. Remove unused rules and combine overlapping rules where possible.' `
            -MITRE $mitreFirewall `
            -CVSSv3Score '3.7' `
            -TechnicalImpact 'Excessive firewall rules increase complexity and the likelihood that overly permissive or outdated rules remain unnoticed.'
        ))
    }

    # ----------------------------------------------------------------
    # Check for no firewall data at all
    # ----------------------------------------------------------------
    if (-not $firewallDataFound) {
        $findings.Add((New-Finding `
            -Id 'WFW-001' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title 'No Windows Firewall configuration data found' `
            -Description "No Windows Firewall profile or rule data was found in the collected evidence. The firewall may be disabled or evidence collection was incomplete." `
            -ArtifactPath '' `
            -Evidence @("No firewall data found in: $firewallDir", "No netsh output found in: $commandsDir") `
            -Recommendation 'Verify that Windows Firewall is enabled. Re-collect firewall evidence using Get-NetFirewallProfile and Get-NetFirewallRule.' `
            -MITRE $mitreFirewall `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Missing firewall data may indicate a completely disabled or absent firewall, leaving all services exposed.'
        ))
    }

    # ----------------------------------------------------------------
    # WFW-007 (Informational): Firewall summary
    # ----------------------------------------------------------------
    $summaryEvidence = @(
        "Firewall profiles found: $($profiles.Count)"
    )

    foreach ($profile in $profiles) {
        $statusStr = if ($profile.Enabled) { 'Enabled' } else { 'DISABLED' }
        $summaryEvidence += "  $($profile.Name) Profile: $statusStr, Inbound: $($profile.DefaultInboundAction), Outbound: $($profile.DefaultOutboundAction)"
    }

    $summaryEvidence += "Total firewall rules parsed: $($firewallRules.Count)"
    $summaryEvidence += "Enabled inbound allow rules: $($enabledAllowInbound.Count)"
    $summaryEvidence += "Disabled profiles: $($disabledProfiles.Count)"
    $summaryEvidence += "Security findings generated: $($findings.Count)"

    $findings.Add((New-Finding `
        -Id 'WFW-007' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Windows Firewall analysis summary' `
        -Description 'Summary of Windows Firewall configuration analysis.' `
        -ArtifactPath $(if (Test-Path $profilesPath) { $profilesPath } elseif ($rulesArtifactPath) { $rulesArtifactPath } else { '' }) `
        -Evidence $summaryEvidence `
        -MITRE $mitreFirewall `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
