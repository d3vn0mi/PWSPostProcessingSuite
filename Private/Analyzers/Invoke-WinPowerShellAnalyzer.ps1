function Invoke-WinPowerShellAnalyzer {
    <#
    .SYNOPSIS
        Analyzes PowerShell history and script block logs for malicious activity.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect all PowerShell content lines for analysis
    $allPSContent = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ----------------------------------------------------------------
    # Read PSReadLine history
    # ----------------------------------------------------------------
    $psHistoryPath = Join-Path $EvidencePath 'security/psreadline_history.txt'
    if (Test-Path $psHistoryPath) {
        $histLines = Read-ArtifactContent -Path $psHistoryPath
        $lineNum = 0
        foreach ($line in $histLines) {
            $lineNum++
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $allPSContent.Add([PSCustomObject]@{
                Text     = $line.Trim()
                Source   = 'security/psreadline_history.txt'
                LineNum  = $lineNum
                Time     = $null
            })
        }
    }

    # ----------------------------------------------------------------
    # Read PowerShell operational event log
    # ----------------------------------------------------------------
    $psEventsPath = Join-Path $EvidencePath 'eventlogs/powershell_events.csv'
    if (Test-Path $psEventsPath) {
        try {
            $psEvents = Import-Csv -Path $psEventsPath -ErrorAction Stop
            foreach ($evt in $psEvents) {
                $msg = ''
                if ($evt.PSObject.Properties['Message']) { $msg = $evt.Message }
                elseif ($evt.PSObject.Properties['message']) { $msg = $evt.message }
                if ([string]::IsNullOrWhiteSpace($msg)) { continue }

                $timeCreated = $null
                foreach ($tf in @('TimeCreated', 'Time', 'Timestamp', 'TimeGenerated')) {
                    if ($evt.PSObject.Properties[$tf] -and -not [string]::IsNullOrWhiteSpace($evt.$tf)) {
                        try { $timeCreated = [datetime]::Parse($evt.$tf) } catch { }
                        if ($null -ne $timeCreated) { break }
                    }
                }

                $allPSContent.Add([PSCustomObject]@{
                    Text     = $msg
                    Source   = 'eventlogs/powershell_events.csv'
                    LineNum  = 0
                    Time     = $timeCreated
                })
            }
        }
        catch {
            Write-Verbose "Failed to parse powershell_events.csv: $_"
        }
    }

    # ----------------------------------------------------------------
    # Read PowerShell script block log
    # ----------------------------------------------------------------
    $psScriptBlockPath = Join-Path $EvidencePath 'eventlogs/powershell_scriptblock.csv'
    if (Test-Path $psScriptBlockPath) {
        try {
            $sbEvents = Import-Csv -Path $psScriptBlockPath -ErrorAction Stop
            foreach ($evt in $sbEvents) {
                $scriptBlock = ''
                foreach ($field in @('ScriptBlockText', 'Message', 'message', 'ScriptBlock')) {
                    if ($evt.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace($evt.$field)) {
                        $scriptBlock = $evt.$field
                        break
                    }
                }
                if ([string]::IsNullOrWhiteSpace($scriptBlock)) { continue }

                $timeCreated = $null
                foreach ($tf in @('TimeCreated', 'Time', 'Timestamp', 'TimeGenerated')) {
                    if ($evt.PSObject.Properties[$tf] -and -not [string]::IsNullOrWhiteSpace($evt.$tf)) {
                        try { $timeCreated = [datetime]::Parse($evt.$tf) } catch { }
                        if ($null -ne $timeCreated) { break }
                    }
                }

                $allPSContent.Add([PSCustomObject]@{
                    Text     = $scriptBlock
                    Source   = 'eventlogs/powershell_scriptblock.csv'
                    LineNum  = 0
                    Time     = $timeCreated
                })
            }
        }
        catch {
            Write-Verbose "Failed to parse powershell_scriptblock.csv: $_"
        }
    }

    if ($allPSContent.Count -eq 0) {
        Write-Verbose 'No PowerShell content found to analyze'
        return $findings.ToArray()
    }

    # ----------------------------------------------------------------
    # WPS-001: Encoded command execution (-enc / -EncodedCommand)
    # ----------------------------------------------------------------
    $encodedCmdPatterns = @(
        '(?i)-e(nc(odedcommand)?)\s+[A-Za-z0-9+/=]{20,}',
        '(?i)powershell.*-e\s+[A-Za-z0-9+/=]{20,}',
        '(?i)\[Convert\]::FromBase64String',
        '(?i)\[System\.Convert\]::FromBase64String',
        '(?i)\[Text\.Encoding\]::UTF8\.GetString.*FromBase64',
        '(?i)certutil.*-decode',
        '(?i)base64\s+--decode'
    )

    $encodedFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $encodedCmdPatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $encodedFindings += "[$($entry.Source)] $snippet"
                break
            }
        }
    }

    if ($encodedFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-001' -Severity 'Critical' -Category 'PowerShell' `
            -Title "Encoded command execution detected ($($encodedFindings.Count) instances)" `
            -Description "Found $($encodedFindings.Count) instance(s) of Base64-encoded command execution. Attackers frequently encode commands to evade detection and logging." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($encodedFindings | Select-Object -First 10) `
            -Recommendation 'Decode all Base64 commands and analyze their content. Investigate the context and user who executed them.' `
            -MITRE 'T1027' `
            -CVSSv3Score '9.1' `
            -TechnicalImpact 'Encoded commands are a primary method for evading security controls and executing malicious payloads including credential theft and lateral movement.'))
    }

    # ----------------------------------------------------------------
    # WPS-002: Known offensive tool detected
    # ----------------------------------------------------------------
    $offensiveToolPatterns = @(
        '(?i)mimikatz', '(?i)Invoke-Mimikatz', '(?i)sekurlsa', '(?i)kerberos::',
        '(?i)PowerSploit', '(?i)Invoke-Shellcode', '(?i)Invoke-ReflectivePEInjection',
        '(?i)Empire', '(?i)Invoke-Empire', '(?i)Stager',
        '(?i)BloodHound', '(?i)SharpHound', '(?i)Invoke-BloodHound',
        '(?i)Rubeus', '(?i)Invoke-Rubeus',
        '(?i)Invoke-Kerberoast', '(?i)Invoke-ASREPRoast',
        '(?i)PowerView', '(?i)Get-NetDomain', '(?i)Get-NetComputer', '(?i)Get-DomainUser',
        '(?i)Invoke-DCSync', '(?i)lsadump',
        '(?i)Invoke-SMBExec', '(?i)Invoke-WMIExec', '(?i)Invoke-PSExec',
        '(?i)Covenant', '(?i)Cobalt\s*Strike', '(?i)beacon',
        '(?i)Invoke-Obfuscation', '(?i)Invoke-CradleCrafter',
        '(?i)LaZagne', '(?i)Invoke-CredentialPhisher',
        '(?i)PowerUp', '(?i)Invoke-AllChecks', '(?i)Invoke-PrivescCheck',
        '(?i)Nishang', '(?i)Invoke-PowerShellTcp'
    )

    # Also check rules engine
    if ($Rules.ContainsKey('suspicious_powershell_commands') -and $Rules['suspicious_powershell_commands'] -is [hashtable]) {
        if ($Rules['suspicious_powershell_commands'].ContainsKey('offensive_tools')) {
            foreach ($rule in $Rules['suspicious_powershell_commands']['offensive_tools']) {
                if ($rule.pattern) { $offensiveToolPatterns += $rule.pattern }
            }
        }
    }

    $offensiveFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $offensiveToolPatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $toolMatch = $Matches[0]
                $offensiveFindings += "[$($entry.Source)] Tool='$toolMatch' : $snippet"
                break
            }
        }
    }

    if ($offensiveFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-002' -Severity 'Critical' -Category 'PowerShell' `
            -Title "Known offensive tool references detected ($($offensiveFindings.Count) instances)" `
            -Description "Found $($offensiveFindings.Count) reference(s) to known offensive security tools (Mimikatz, PowerSploit, Empire, BloodHound, etc.) in PowerShell logs." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($offensiveFindings | Select-Object -First 10) `
            -Recommendation 'This is a critical indicator of compromise. Investigate immediately, isolate the system, and perform full incident response.' `
            -MITRE 'T1059.001' `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Offensive tools enable credential dumping, privilege escalation, lateral movement, and domain compromise.'))
    }

    # ----------------------------------------------------------------
    # WPS-003: Download cradle detected
    # ----------------------------------------------------------------
    $downloadCradlePatterns = @(
        '(?i)(New-Object\s+Net\.WebClient).*DownloadString',
        '(?i)DownloadString\s*\(',
        '(?i)DownloadFile\s*\(',
        '(?i)DownloadData\s*\(',
        '(?i)Invoke-WebRequest.*\|\s*Invoke-Expression',
        '(?i)Invoke-WebRequest.*\|\s*iex',
        '(?i)iwr\s.*\|\s*iex',
        '(?i)curl\s.*\|\s*iex',
        '(?i)wget\s.*\|\s*iex',
        '(?i)Invoke-RestMethod.*\|\s*Invoke-Expression',
        '(?i)irm\s.*\|\s*iex',
        '(?i)\(New-Object\s+Net\.WebClient\)\.DownloadString',
        '(?i)Start-BitsTransfer',
        '(?i)certutil.*-urlcache.*-split.*-f',
        '(?i)bitsadmin.*\/transfer'
    )

    $cradleFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $downloadCradlePatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $cradleFindings += "[$($entry.Source)] $snippet"
                break
            }
        }
    }

    if ($cradleFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-003' -Severity 'High' -Category 'PowerShell' `
            -Title "Download cradle detected ($($cradleFindings.Count) instances)" `
            -Description "Found $($cradleFindings.Count) instance(s) of download cradle patterns (DownloadString, IEX, Invoke-WebRequest|IEX). These are commonly used to download and execute malicious payloads." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($cradleFindings | Select-Object -First 10) `
            -Recommendation 'Investigate the URLs being accessed. Check for downloaded payloads and determine what was executed.' `
            -MITRE 'T1105' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Download cradles fetch and execute remote payloads, enabling initial access, malware delivery, and second-stage implant deployment.'))
    }

    # ----------------------------------------------------------------
    # WPS-004: AMSI bypass detected
    # ----------------------------------------------------------------
    $amsiBypassPatterns = @(
        '(?i)amsiInitFailed',
        '(?i)AmsiUtils',
        '(?i)amsiContext',
        '(?i)AmsiScanBuffer',
        '(?i)Disable-Amsi',
        '(?i)Bypass-AMSI',
        '(?i)Set-MpPreference.*DisableRealtimeMonitoring',
        '(?i)\[Ref\]\.Assembly\.GetType.*AMSIUtils',
        '(?i)amsi\.dll',
        '(?i)AmsiOpenSession',
        '(?i)Remove-Amsi'
    )

    $amsiFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $amsiBypassPatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $amsiFindings += "[$($entry.Source)] $snippet"
                break
            }
        }
    }

    if ($amsiFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-004' -Severity 'High' -Category 'PowerShell' `
            -Title "AMSI bypass detected ($($amsiFindings.Count) instances)" `
            -Description "Found $($amsiFindings.Count) instance(s) of AMSI (Antimalware Scan Interface) bypass attempts. AMSI bypass disables real-time script scanning, allowing malicious code execution." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($amsiFindings | Select-Object -First 10) `
            -Recommendation 'AMSI bypass is a strong indicator of malicious activity. Investigate all related commands and check for further compromise.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'AMSI bypass disables real-time script content scanning, allowing malware and offensive tools to execute undetected by security software.'))
    }

    # ----------------------------------------------------------------
    # WPS-005: Defender tampering commands
    # ----------------------------------------------------------------
    $defenderTamperPatterns = @(
        '(?i)Set-MpPreference.*-DisableRealtimeMonitoring\s+\$true',
        '(?i)Set-MpPreference.*-DisableBehaviorMonitoring\s+\$true',
        '(?i)Set-MpPreference.*-DisableBlockAtFirstSeen\s+\$true',
        '(?i)Set-MpPreference.*-DisableIOAVProtection\s+\$true',
        '(?i)Set-MpPreference.*-DisableScriptScanning\s+\$true',
        '(?i)Set-MpPreference.*-ExclusionPath',
        '(?i)Set-MpPreference.*-ExclusionProcess',
        '(?i)Set-MpPreference.*-ExclusionExtension',
        '(?i)Add-MpPreference.*-ExclusionPath',
        '(?i)Add-MpPreference.*-ExclusionProcess',
        '(?i)Add-MpPreference.*-ExclusionExtension',
        '(?i)Set-MpPreference.*-DisableAntiSpyware',
        '(?i)sc\s+(stop|delete|config)\s+WinDefend',
        '(?i)net\s+stop\s+WinDefend',
        '(?i)Uninstall-WindowsFeature.*Windows-Defender'
    )

    $defenderFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $defenderTamperPatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $defenderFindings += "[$($entry.Source)] $snippet"
                break
            }
        }
    }

    if ($defenderFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-005' -Severity 'High' -Category 'PowerShell' `
            -Title "Defender tampering commands detected ($($defenderFindings.Count) instances)" `
            -Description "Found $($defenderFindings.Count) instance(s) of commands that disable or modify Windows Defender settings, including disabling real-time protection or adding exclusions." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($defenderFindings | Select-Object -First 10) `
            -Recommendation 'Investigate who executed these commands and why. Re-enable Defender protections and remove unauthorized exclusions.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Disabling Defender allows malware to execute undetected. Adding exclusions creates blind spots that attackers exploit for persistence.'))
    }

    # ----------------------------------------------------------------
    # WPS-006: Execution policy bypass
    # ----------------------------------------------------------------
    $execPolicyPatterns = @(
        '(?i)-ExecutionPolicy\s+Bypass',
        '(?i)-ep\s+bypass',
        '(?i)Set-ExecutionPolicy\s+(Unrestricted|Bypass|RemoteSigned)',
        '(?i)powershell.*-nop.*-exec\s+bypass'
    )

    $execPolicyFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $execPolicyPatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $execPolicyFindings += "[$($entry.Source)] $snippet"
                break
            }
        }
    }

    if ($execPolicyFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-006' -Severity 'Medium' -Category 'PowerShell' `
            -Title "Execution policy bypass detected ($($execPolicyFindings.Count) instances)" `
            -Description "Found $($execPolicyFindings.Count) instance(s) of PowerShell execution policy bypass. While not a security boundary, this is commonly seen in attack chains." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($execPolicyFindings | Select-Object -First 10) `
            -Recommendation 'Review the commands executed with bypassed execution policy. Enforce execution policy via Group Policy for defense in depth.' `
            -MITRE 'T1059.001' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Execution policy bypass allows running unsigned scripts, which is a common step in attack chains for malware deployment.'))
    }

    # ----------------------------------------------------------------
    # WPS-007: Event log clearing commands
    # ----------------------------------------------------------------
    $logClearPatterns = @(
        '(?i)Clear-EventLog',
        '(?i)wevtutil\s+(cl|clear-log)',
        '(?i)Remove-EventLog',
        '(?i)wevtutil\s+el.*\|\s*.*wevtutil\s+cl',
        '(?i)Get-WinEvent.*\|\s*Remove',
        '(?i)del\s+.*\\Security\.evtx',
        '(?i)Remove-Item.*\.evtx'
    )

    $logClearFindings = @()
    foreach ($entry in $allPSContent) {
        foreach ($pattern in $logClearPatterns) {
            if ($entry.Text -match $pattern) {
                $snippet = if ($entry.Text.Length -gt 200) { $entry.Text.Substring(0, 200) + '...' } else { $entry.Text }
                $logClearFindings += "[$($entry.Source)] $snippet"
                break
            }
        }
    }

    if ($logClearFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPS-007' -Severity 'High' -Category 'PowerShell' `
            -Title "Event log clearing commands detected ($($logClearFindings.Count) instances)" `
            -Description "Found $($logClearFindings.Count) instance(s) of commands that clear Windows event logs. This is a strong indicator of anti-forensic activity." `
            -ArtifactPath 'security/psreadline_history.txt' `
            -Evidence @($logClearFindings | Select-Object -First 10) `
            -Recommendation 'Investigate who cleared the logs and why. Implement log forwarding to a SIEM to prevent evidence destruction.' `
            -MITRE 'T1070.001' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Clearing event logs destroys forensic evidence of attacker activity, making incident investigation significantly harder.'))
    }

    # ----------------------------------------------------------------
    # WPS-008: PowerShell activity summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()
    $summaryItems += "Total PowerShell entries analyzed: $($allPSContent.Count)"

    # Count by source
    $bySource = $allPSContent | Group-Object -Property Source
    foreach ($group in $bySource) {
        $summaryItems += "Source '$($group.Name)': $($group.Count) entries"
    }

    # Check if rules-based pattern matching was used
    if ($Rules.ContainsKey('suspicious_powershell_commands') -and $Rules['suspicious_powershell_commands'] -is [hashtable]) {
        $ruleCategories = $Rules['suspicious_powershell_commands'].Keys -join ', '
        $summaryItems += "Rules engine categories checked: $ruleCategories"

        # Run Test-PatternMatch against each subcategory
        foreach ($category in $Rules['suspicious_powershell_commands'].Keys) {
            $patterns = $Rules['suspicious_powershell_commands'][$category]
            if ($patterns -isnot [array]) { continue }

            $matchCount = 0
            foreach ($entry in $allPSContent) {
                $result = Test-PatternMatch -InputText $entry.Text -Patterns $patterns
                if ($result.Matched) { $matchCount++ }
            }
            if ($matchCount -gt 0) {
                $summaryItems += "Rules category '$category': $matchCount matches"
            }
        }
    }

    $summaryItems += "Encoded commands found: $($encodedFindings.Count)"
    $summaryItems += "Offensive tool references: $($offensiveFindings.Count)"
    $summaryItems += "Download cradles: $($cradleFindings.Count)"
    $summaryItems += "AMSI bypass attempts: $($amsiFindings.Count)"
    $summaryItems += "Defender tampering: $($defenderFindings.Count)"
    $summaryItems += "Execution policy bypasses: $($execPolicyFindings.Count)"
    $summaryItems += "Log clearing commands: $($logClearFindings.Count)"

    $findings.Add((New-Finding -Id 'WPS-008' -Severity 'Informational' -Category 'PowerShell' `
        -Title 'PowerShell activity summary' `
        -Description 'Summary of PowerShell history and script block log analysis.' `
        -ArtifactPath 'security/psreadline_history.txt' `
        -Evidence $summaryItems `
        -Recommendation 'Review the summary for indicators of compromise and correlate with other findings.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of PowerShell activity on the system.'))

    return $findings.ToArray()
}
