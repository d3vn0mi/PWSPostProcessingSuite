function Invoke-WinProcessAnalyzer {
    <#
    .SYNOPSIS
        Analyzes running processes for suspicious activity and indicators of compromise.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Load process data
    $processCsvPath = Join-Path $EvidencePath 'collected_commands/process_list.csv'
    $tasklistPath = Join-Path $EvidencePath 'collected_commands/tasklist.txt'

    $processes = @()

    if (Test-Path $processCsvPath) {
        $csvLines = Read-ArtifactContent -Path $processCsvPath
        $csvContent = $csvLines -join "`n"
        try {
            $parsed = $csvContent | ConvertFrom-Csv -ErrorAction Stop
            foreach ($row in $parsed) {
                $processes += [PSCustomObject]@{
                    Name            = if ($row.PSObject.Properties['Name']) { $row.Name } else { '' }
                    ProcessId       = if ($row.PSObject.Properties['ProcessId']) { $row.ProcessId } else { '' }
                    CommandLine     = if ($row.PSObject.Properties['CommandLine']) { $row.CommandLine } else { '' }
                    ExecutablePath  = if ($row.PSObject.Properties['ExecutablePath']) { $row.ExecutablePath } else { '' }
                    ParentProcessId = if ($row.PSObject.Properties['ParentProcessId']) { $row.ParentProcessId } else { '' }
                }
            }
        }
        catch {
            Write-Verbose "WinProcessAnalyzer: Failed to parse process_list.csv: $_"
        }
    }
    elseif (Test-Path $tasklistPath) {
        # Fallback: parse tasklist.txt output
        $taskLines = Read-ArtifactContent -Path $tasklistPath
        foreach ($line in $taskLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($trimmed -match '^=+' -or $trimmed -match '^Image Name\s') { continue }

            # tasklist format: Image Name  PID  Session Name  Session#  Mem Usage
            if ($trimmed -match '^(.+?)\s{2,}(\d+)\s{2,}') {
                $procName = $Matches[1].Trim()
                $procPid = $Matches[2].Trim()
                $processes += [PSCustomObject]@{
                    Name            = $procName
                    ProcessId       = $procPid
                    CommandLine     = ''
                    ExecutablePath  = ''
                    ParentProcessId = ''
                }
            }
        }
    }

    if ($processes.Count -eq 0) {
        $findings.Add((New-Finding -Id 'WPROC-008' -Severity 'Informational' -Category 'Processes' `
            -Title 'Process analysis summary' `
            -Description 'No process data was found in the collected evidence.' `
            -ArtifactPath '' `
            -Evidence @('No process_list.csv or tasklist.txt found in collected_commands/') `
            -Recommendation 'Ensure process data is collected during evidence gathering using Get-CimInstance Win32_Process or tasklist.' `
            -MITRE '' `
            -CVSSv3Score '' `
            -TechnicalImpact 'Unable to perform process analysis without collected process data.'))
        return $findings.ToArray()
    }

    # Build process lookup by PID for parent resolution
    $pidLookup = @{}
    foreach ($proc in $processes) {
        if (-not [string]::IsNullOrWhiteSpace($proc.ProcessId)) {
            $pidLookup[$proc.ProcessId] = $proc
        }
    }

    # ----------------------------------------------------------------
    # WPROC-001: Process with encoded PowerShell command line
    # ----------------------------------------------------------------
    $encodedPsProcesses = @()
    $encodedPatterns = @(
        '-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]',
        '-[Ee][Cc]\s',
        '-[Ee][Nn][Cc]\s',
        'FromBase64String',
        '\[Convert\]::FromBase64',
        '-encodedcommand\s',
        '-EncodedCommand\s'
    )

    foreach ($proc in $processes) {
        if ([string]::IsNullOrWhiteSpace($proc.CommandLine)) { continue }
        foreach ($pattern in $encodedPatterns) {
            if ($proc.CommandLine -match $pattern) {
                $cmdSnippet = $proc.CommandLine
                if ($cmdSnippet.Length -gt 300) { $cmdSnippet = $cmdSnippet.Substring(0, 300) + '...' }
                $encodedPsProcesses += "PID $($proc.ProcessId) ($($proc.Name)): $cmdSnippet"
                break
            }
        }
    }

    if ($encodedPsProcesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-001' -Severity 'Critical' -Category 'Processes' `
            -Title 'Process with encoded PowerShell command line' `
            -Description "Found $($encodedPsProcesses.Count) process(es) using encoded PowerShell commands. Encoded commands are commonly used to obfuscate malicious payloads and bypass detection." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($encodedPsProcesses | Select-Object -First 10) `
            -Recommendation 'Decode the Base64 command content and analyze the script. Encoded PowerShell is a strong indicator of malicious activity unless part of known automation tools.' `
            -MITRE 'T1059.001' `
            -CVSSv3Score '9.1' `
            -TechnicalImpact 'Encoded PowerShell commands indicate potential malware execution, payload delivery, or C2 communication using obfuscation to evade endpoint detection.'))
    }

    # ----------------------------------------------------------------
    # WPROC-002: Process running from Temp/AppData/Public directory
    # ----------------------------------------------------------------
    $tempProcesses = @()
    $suspiciousDirs = @('\\Temp\\', '\\tmp\\', '\\AppData\\Local\\Temp', '\\AppData\\Roaming\\', '\\Public\\', '\\Downloads\\', '\\ProgramData\\Temp')

    foreach ($proc in $processes) {
        $execPath = $proc.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($execPath)) { continue }

        foreach ($dir in $suspiciousDirs) {
            if ($execPath -match [regex]::Escape($dir)) {
                $tempProcesses += "PID $($proc.ProcessId) ($($proc.Name)): $execPath"
                break
            }
        }
    }

    if ($tempProcesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-002' -Severity 'High' -Category 'Processes' `
            -Title 'Process running from Temp, AppData, or Public directory' `
            -Description "Found $($tempProcesses.Count) process(es) executing from temporary or user-writable directories. Malware frequently stages and executes payloads from these locations to avoid detection." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($tempProcesses | Select-Object -First 10) `
            -Recommendation 'Investigate each process running from a temporary directory. Legitimate software rarely executes from Temp or Public folders. Check file hashes against threat intelligence sources.' `
            -MITRE 'T1204.002' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Processes executing from temporary directories indicate potential malware staging, dropper activity, or exploitation payloads that write and execute from user-writable locations.'))
    }

    # ----------------------------------------------------------------
    # WPROC-003: LOLBin process with suspicious command line
    # ----------------------------------------------------------------
    $defaultLolbins = @{
        'certutil'  = @('-urlcache', '-decode', '-encode', '-verifyctl', 'http://', 'https://', 'ftp://')
        'mshta'     = @('http://', 'https://', 'javascript:', 'vbscript:')
        'regsvr32'  = @('/s /i:http', '/s /i:https', '/s /n /u', 'scrobj.dll')
        'rundll32'  = @('javascript:', 'http://', 'shell32.dll,ShellExec_RunDLL', 'advpack.dll,RegisterOCX')
        'msiexec'   = @('/q', 'http://', 'https://')
        'bitsadmin' = @('/transfer', '/addfile', 'http://', 'https://')
        'cscript'   = @('http://', 'https://', '\\\\')
        'wscript'   = @('http://', 'https://', '\\\\')
        'wmic'      = @('process call create', '/node:', 'os get', 'http://', 'https://')
        'cmd'       = @('/c powershell', '/c certutil', '/c bitsadmin', '/c mshta')
    }

    # Use Rules['lolbins'] if available, otherwise use defaults
    $lolbinDefs = $defaultLolbins
    if ($Rules.ContainsKey('lolbins') -and $Rules['lolbins'] -is [hashtable]) {
        $lolbinDefs = $Rules['lolbins']
    }

    $lolbinFindings = @()

    foreach ($proc in $processes) {
        if ([string]::IsNullOrWhiteSpace($proc.CommandLine)) { continue }
        $procNameLower = $proc.Name.ToLower() -replace '\.exe$', ''

        foreach ($lolbin in $lolbinDefs.Keys) {
            if ($procNameLower -eq $lolbin.ToLower()) {
                foreach ($indicator in $lolbinDefs[$lolbin]) {
                    if ($proc.CommandLine -match [regex]::Escape($indicator)) {
                        $cmdSnippet = $proc.CommandLine
                        if ($cmdSnippet.Length -gt 250) { $cmdSnippet = $cmdSnippet.Substring(0, 250) + '...' }
                        $lolbinFindings += "PID $($proc.ProcessId) ($($proc.Name)) matched '$indicator': $cmdSnippet"
                        break
                    }
                }
                break
            }
        }
    }

    if ($lolbinFindings.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-003' -Severity 'High' -Category 'Processes' `
            -Title 'LOLBin process with suspicious command line' `
            -Description "Found $($lolbinFindings.Count) Living-off-the-Land Binary (LOLBin) process(es) with suspicious command-line arguments. Attackers abuse legitimate system binaries to download payloads, execute code, and bypass application whitelisting." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($lolbinFindings | Select-Object -First 10) `
            -Recommendation 'Investigate each LOLBin usage. Review the full command line and correlate with user activity. Implement AppLocker or WDAC policies to restrict LOLBin abuse.' `
            -MITRE 'T1218' `
            -CVSSv3Score '7.8' `
            -TechnicalImpact 'LOLBin abuse enables attackers to download malware, execute arbitrary code, and bypass application whitelisting using trusted Microsoft-signed binaries.'))
    }

    # ----------------------------------------------------------------
    # WPROC-004: Process with no executable path (possible hollowing)
    # ----------------------------------------------------------------
    $noPathProcesses = @()
    # System processes that legitimately may not have a path
    $systemProcesses = @('System', 'Idle', 'Registry', 'Memory Compression', 'System Idle Process', 'Secure System', 'vmmem')

    foreach ($proc in $processes) {
        if ($proc.Name -in $systemProcesses) { continue }
        if ([string]::IsNullOrWhiteSpace($proc.ExecutablePath) -and -not [string]::IsNullOrWhiteSpace($proc.Name)) {
            # Only flag if we have CSV data (tasklist fallback won't have paths)
            if (Test-Path $processCsvPath) {
                $noPathProcesses += "PID $($proc.ProcessId) ($($proc.Name)): No executable path"
            }
        }
    }

    if ($noPathProcesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-004' -Severity 'High' -Category 'Processes' `
            -Title 'Process with no executable path detected' `
            -Description "Found $($noPathProcesses.Count) process(es) with no associated executable path. This can indicate process hollowing, memory-only execution, or processes whose binaries have been deleted after launch." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($noPathProcesses | Select-Object -First 10) `
            -Recommendation 'Investigate processes without executable paths using memory forensics tools. Check if the process binary was deleted post-execution or if process hollowing techniques were used.' `
            -MITRE 'T1055.012' `
            -CVSSv3Score '7.8' `
            -TechnicalImpact 'Processes without executable paths suggest fileless malware, process hollowing, or memory-only payloads that evade traditional file-based detection.'))
    }

    # ----------------------------------------------------------------
    # WPROC-005: cmd.exe or powershell.exe spawned by unusual parent
    # ----------------------------------------------------------------
    $unusualShellParents = @()
    $shellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'conhost.exe')
    $normalShellParents = @('explorer.exe', 'svchost.exe', 'services.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
        'WindowsTerminal.exe', 'conhost.exe', 'Code.exe', 'devenv.exe', 'taskmgr.exe',
        'RuntimeBroker.exe', 'ShellExperienceHost.exe', 'winlogon.exe', 'csrss.exe', 'wininit.exe')

    foreach ($proc in $processes) {
        if ($proc.Name -notin $shellNames) { continue }
        if ([string]::IsNullOrWhiteSpace($proc.ParentProcessId)) { continue }

        $parent = $null
        if ($pidLookup.ContainsKey($proc.ParentProcessId)) {
            $parent = $pidLookup[$proc.ParentProcessId]
        }

        if ($null -ne $parent -and $parent.Name -notin $normalShellParents) {
            $cmdSnippet = $proc.CommandLine
            if (-not [string]::IsNullOrWhiteSpace($cmdSnippet) -and $cmdSnippet.Length -gt 200) {
                $cmdSnippet = $cmdSnippet.Substring(0, 200) + '...'
            }
            $unusualShellParents += "PID $($proc.ProcessId) ($($proc.Name)) spawned by PID $($parent.ProcessId) ($($parent.Name))$(if ($cmdSnippet) { ": $cmdSnippet" })"
        }
    }

    if ($unusualShellParents.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-005' -Severity 'Medium' -Category 'Processes' `
            -Title 'Shell process spawned by unusual parent' `
            -Description "Found $($unusualShellParents.Count) cmd.exe/powershell.exe instance(s) spawned by unusual parent processes. Malware and exploits often spawn shells from processes like Word, Excel, or browser processes." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($unusualShellParents | Select-Object -First 10) `
            -Recommendation 'Investigate each unusual parent-child process relationship. Document or Office applications spawning cmd.exe or powershell.exe is a strong indicator of macro-based malware or exploitation.' `
            -MITRE 'T1059' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Unusual parent-child process relationships indicate potential exploitation, macro malware, or lateral movement tools spawning interactive shells.'))
    }

    # ----------------------------------------------------------------
    # WPROC-006: Multiple instances of same rare process
    # ----------------------------------------------------------------
    # Common processes that legitimately have many instances
    $commonMultiInstance = @('svchost.exe', 'RuntimeBroker.exe', 'conhost.exe', 'dllhost.exe',
        'taskhostw.exe', 'backgroundTaskHost.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
        'SearchProtocolHost.exe', 'WmiPrvSE.exe', 'csrss.exe', 'wininit.exe', 'System',
        'Idle', 'explorer.exe', 'sihost.exe', 'ctfmon.exe', 'MsMpEng.exe')

    $procCounts = @{}
    foreach ($proc in $processes) {
        if ([string]::IsNullOrWhiteSpace($proc.Name)) { continue }
        if ($proc.Name -in $commonMultiInstance) { continue }
        if (-not $procCounts.ContainsKey($proc.Name)) {
            $procCounts[$proc.Name] = @()
        }
        $procCounts[$proc.Name] += $proc
    }

    $duplicateProcesses = @()
    foreach ($name in $procCounts.Keys) {
        if ($procCounts[$name].Count -ge 3) {
            $pids = ($procCounts[$name] | ForEach-Object { $_.ProcessId }) -join ', '
            $duplicateProcesses += "$name: $($procCounts[$name].Count) instances (PIDs: $pids)"
        }
    }

    if ($duplicateProcesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-006' -Severity 'Medium' -Category 'Processes' `
            -Title 'Multiple instances of uncommon process detected' `
            -Description "Found $($duplicateProcesses.Count) process name(s) with 3 or more instances that are not typically multi-instance. This may indicate process injection, malware spawning, or repeated exploitation attempts." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($duplicateProcesses | Select-Object -First 10) `
            -Recommendation 'Investigate why multiple instances of these processes are running. Compare executable paths and command lines across instances to detect anomalies.' `
            -MITRE 'T1055' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Multiple instances of uncommon processes can indicate process injection, malware spawning copies for redundancy, or exploitation attempts creating orphaned processes.'))
    }

    # ----------------------------------------------------------------
    # WPROC-007: Process name mimicking system process from wrong path
    # ----------------------------------------------------------------
    $systemProcessPaths = @{
        'svchost.exe'  = 'C:\Windows\System32\svchost.exe'
        'csrss.exe'    = 'C:\Windows\System32\csrss.exe'
        'lsass.exe'    = 'C:\Windows\System32\lsass.exe'
        'services.exe' = 'C:\Windows\System32\services.exe'
        'smss.exe'     = 'C:\Windows\System32\smss.exe'
        'wininit.exe'  = 'C:\Windows\System32\wininit.exe'
        'winlogon.exe' = 'C:\Windows\System32\winlogon.exe'
        'explorer.exe' = 'C:\Windows\explorer.exe'
        'spoolsv.exe'  = 'C:\Windows\System32\spoolsv.exe'
        'taskhost.exe' = 'C:\Windows\System32\taskhost.exe'
        'taskhostw.exe' = 'C:\Windows\System32\taskhostw.exe'
        'conhost.exe'  = 'C:\Windows\System32\conhost.exe'
        'dwm.exe'      = 'C:\Windows\System32\dwm.exe'
        'dllhost.exe'  = 'C:\Windows\System32\dllhost.exe'
    }

    $masqueradingProcesses = @()

    foreach ($proc in $processes) {
        if ([string]::IsNullOrWhiteSpace($proc.ExecutablePath)) { continue }
        $nameLower = $proc.Name.ToLower()

        if ($systemProcessPaths.ContainsKey($nameLower)) {
            $expectedPath = $systemProcessPaths[$nameLower]
            if ($proc.ExecutablePath -ne $expectedPath -and $proc.ExecutablePath.ToLower() -ne $expectedPath.ToLower()) {
                # Allow SysWOW64 variants
                if ($proc.ExecutablePath -match 'SysWOW64') { continue }
                $masqueradingProcesses += "PID $($proc.ProcessId) ($($proc.Name)): Expected '$expectedPath', Found '$($proc.ExecutablePath)'"
            }
        }
    }

    if ($masqueradingProcesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WPROC-007' -Severity 'High' -Category 'Processes' `
            -Title 'Process name mimicking system process from unexpected path' `
            -Description "Found $($masqueradingProcesses.Count) process(es) with names matching critical system processes but running from unexpected locations. This is a common masquerading technique used by malware to blend in with legitimate system activity." `
            -ArtifactPath 'collected_commands/process_list.csv' `
            -Evidence @($masqueradingProcesses | Select-Object -First 10) `
            -Recommendation 'Immediately investigate processes masquerading as system binaries. Compare file hashes with known-good Microsoft binaries. This is a strong indicator of malware attempting to evade detection.' `
            -MITRE 'T1036.005' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Process masquerading indicates active malware attempting to hide among legitimate system processes, suggesting a compromised system with running malicious code.'))
    }

    # ----------------------------------------------------------------
    # WPROC-008: Process summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()
    $summaryItems += "Total processes analyzed: $($processes.Count)"

    if (Test-Path $processCsvPath) {
        $summaryItems += 'Source: collected_commands/process_list.csv (Get-CimInstance Win32_Process)'
    }
    elseif (Test-Path $tasklistPath) {
        $summaryItems += 'Source: collected_commands/tasklist.txt (limited data - no command lines or paths)'
    }

    $withCmdLine = ($processes | Where-Object { -not [string]::IsNullOrWhiteSpace($_.CommandLine) }).Count
    $withPath = ($processes | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) }).Count
    $summaryItems += "Processes with command line data: $withCmdLine"
    $summaryItems += "Processes with executable path: $withPath"

    $uniqueNames = ($processes | Select-Object -ExpandProperty Name -Unique).Count
    $summaryItems += "Unique process names: $uniqueNames"

    # Top processes by instance count
    $allCounts = @{}
    foreach ($proc in $processes) {
        if ([string]::IsNullOrWhiteSpace($proc.Name)) { continue }
        if (-not $allCounts.ContainsKey($proc.Name)) { $allCounts[$proc.Name] = 0 }
        $allCounts[$proc.Name]++
    }
    $topProcs = $allCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    foreach ($tp in $topProcs) {
        $summaryItems += "  $($tp.Key): $($tp.Value) instance(s)"
    }

    $findings.Add((New-Finding -Id 'WPROC-008' -Severity 'Informational' -Category 'Processes' `
        -Title 'Process analysis summary' `
        -Description 'Summary of running process analysis from collected evidence.' `
        -ArtifactPath 'collected_commands/process_list.csv' `
        -Evidence @($summaryItems | Select-Object -First 20) `
        -Recommendation 'Review the process summary for overall system posture. Correlate findings with other analyzer results for comprehensive threat assessment.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of running process landscape.'))

    return $findings.ToArray()
}
