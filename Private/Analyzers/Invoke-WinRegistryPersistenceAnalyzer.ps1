function Invoke-WinRegistryPersistenceAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows registry-based persistence mechanisms for security issues.
    .DESCRIPTION
        Examines collected registry data for persistence mechanisms including Run/RunOnce
        keys, Winlogon modifications, Image File Execution Options debuggers, AppInit_DLLs,
        and BootExecute values. Identifies suspicious executables, LOLBin usage, and
        non-default configuration values that may indicate compromise.
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
    $analyzerCategory = 'Windows Registry Persistence'
    $mitrePersistence = 'T1547.001'

    # ----------------------------------------------------------------
    # Load artifacts
    # ----------------------------------------------------------------
    $registryDir = Join-Path $EvidencePath 'registry'

    $runKeysPath = Join-Path $registryDir 'run_keys.txt'
    $winlogonPath = Join-Path $registryDir 'winlogon.txt'
    $ifeoPath = Join-Path $registryDir 'ifeo.txt'
    $appinitPath = Join-Path $registryDir 'appinit_dlls.txt'
    $bootExecPath = Join-Path $registryDir 'boot_execute.txt'

    if (-not (Test-Path $registryDir)) {
        Write-Verbose "WinRegistryPersistenceAnalyzer: Registry directory not found, skipping."
        return @()
    }

    # Get suspicious patterns from rules
    $suspiciousPatterns = @()
    if ($Rules -and $Rules.ContainsKey('suspicious_task_patterns')) {
        $suspiciousPatterns = $Rules['suspicious_task_patterns']
    }

    # Suspicious path patterns for direct matching
    $suspiciousPathPatterns = @(
        '\\Temp\\', '\\tmp\\', '\\AppData\\Local\\Temp\\',
        '\\Downloads\\', '\\Public\\', '\\ProgramData\\',
        '\\Users\\Public\\', '\\Recycle', '\\Windows\\Temp\\'
    )

    # User-writable location patterns
    $userWritablePatterns = @(
        '\\Users\\[^\\]+\\AppData\\', '\\Users\\[^\\]+\\Desktop\\',
        '\\Users\\[^\\]+\\Documents\\', '\\Users\\[^\\]+\\Downloads\\',
        '\\Users\\Public\\', '\\Temp\\', '\\tmp\\'
    )

    # Encoded command / LOLBin patterns for direct detection
    $encodedCmdPatterns = @(
        '(?i)-[eE]nc(?:odedCommand)?\s+',
        '(?i)powershell.*-e\s+[A-Za-z0-9+/=]{20,}',
        '(?i)cmd\.exe\s+/c.*powershell',
        '(?i)mshta\s+',
        '(?i)regsvr32\s+/s\s+/n\s+/u\s+/i:',
        '(?i)rundll32\s+',
        '(?i)certutil.*-urlcache',
        '(?i)bitsadmin.*\/transfer',
        '(?i)wscript\s+',
        '(?i)cscript\s+'
    )

    # Track all run key entries for summary
    $allRunKeyEntries = [System.Collections.Generic.List[string]]::new()
    $totalPersistencePoints = 0

    # ----------------------------------------------------------------
    # Parse registry files - format: "Name = Value" lines
    # ----------------------------------------------------------------
    function Read-RegistryFile {
        param([string]$Path)
        $entries = [System.Collections.Generic.List[hashtable]]::new()
        if (-not (Test-Path $Path)) { return $entries }

        $content = Get-Content -Path $Path -ErrorAction SilentlyContinue
        $currentKey = ''
        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            # Registry key path header (e.g., "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
            if ($trimmed -match '^(HKLM|HKCU|HKU|HKCR|HKCC)[:\\]' -or $trimmed -match '^(Computer\\)?HK') {
                $currentKey = $trimmed
                continue
            }

            # Name = Value pair
            if ($trimmed -match '^\s*(.+?)\s*[=:]\s*(.+)$') {
                $entryName = $Matches[1].Trim()
                $entryValue = $Matches[2].Trim()
                # Skip property headers or type annotations
                if ($entryName -match '^(PSPath|PSParentPath|PSChildName|PSProvider|PSDrive)$') { continue }
                $entries.Add(@{
                    Key      = $currentKey
                    Name     = $entryName
                    Value    = $entryValue
                    RawLine  = $trimmed
                    FullPath = if ($currentKey) { "$currentKey\$entryName" } else { $entryName }
                })
            }
        }
        return $entries
    }

    # ----------------------------------------------------------------
    # Analyze Run keys
    # ----------------------------------------------------------------
    if (Test-Path $runKeysPath) {
        $runEntries = Read-RegistryFile -Path $runKeysPath

        foreach ($entry in $runEntries) {
            $allRunKeyEntries.Add("$($entry.Name) = $($entry.Value)")
            $totalPersistencePoints++
            $value = $entry.Value

            # WREG-001: Suspicious executable in Run keys (encoded commands, LOLBins)
            $isSuspicious = $false
            $matchedPattern = ''

            # Check against Rules patterns first
            if ($suspiciousPatterns.Count -gt 0) {
                $patternResult = Test-PatternMatch -InputText $value -Patterns $suspiciousPatterns
                if ($patternResult.Matched) {
                    $isSuspicious = $true
                    $matchedPattern = $patternResult.RuleName
                }
            }

            # Check against built-in encoded command / LOLBin patterns
            if (-not $isSuspicious) {
                foreach ($pattern in $encodedCmdPatterns) {
                    if ($value -match $pattern) {
                        $isSuspicious = $true
                        $matchedPattern = $pattern
                        break
                    }
                }
            }

            # Check for suspicious temp/download paths
            if (-not $isSuspicious) {
                foreach ($pathPattern in $suspiciousPathPatterns) {
                    if ($value -match [regex]::Escape($pathPattern).Replace('\\\*', '.*')) {
                        # Only flag as suspicious if combined with execution
                        if ($value -match '(?i)\.(exe|bat|cmd|vbs|js|ps1|wsf|scr|com|pif)') {
                            $isSuspicious = $true
                            $matchedPattern = "Executable in suspicious path: $pathPattern"
                            break
                        }
                    }
                }
            }

            if ($isSuspicious) {
                $findings.Add((New-Finding `
                    -Id 'WREG-001' `
                    -Severity 'Critical' `
                    -Category $analyzerCategory `
                    -Title "Suspicious executable in Run key: $($entry.Name)" `
                    -Description "Registry Run key contains a suspicious entry that matches known malicious patterns. Entry: $($entry.Name) in $($entry.Key)." `
                    -ArtifactPath $runKeysPath `
                    -Evidence @("Key: $($entry.Key)", "Name: $($entry.Name)", "Value: $value", "Matched pattern: $matchedPattern") `
                    -Recommendation 'Investigate this Run key entry immediately. Analyze the referenced executable. Remove if confirmed malicious.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'Malicious Run key entries execute automatically at user logon, providing persistent access and potential for credential theft or lateral movement.'
                ))
                continue
            }

            # WREG-007: Run key entry points to user-writable location
            $isUserWritable = $false
            foreach ($uwPattern in $userWritablePatterns) {
                if ($value -match $uwPattern) {
                    $isUserWritable = $true
                    break
                }
            }

            if ($isUserWritable) {
                $findings.Add((New-Finding `
                    -Id 'WREG-007' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "Run key points to user-writable location: $($entry.Name)" `
                    -Description "Registry Run key '$($entry.Name)' references a binary in a user-writable location. An attacker could replace this binary to gain persistence." `
                    -ArtifactPath $runKeysPath `
                    -Evidence @("Key: $($entry.Key)", "Name: $($entry.Name)", "Value: $value") `
                    -Recommendation 'Move the referenced executable to a protected location (Program Files) or remove the Run key if not needed.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '7.8' `
                    -TechnicalImpact 'Run key pointing to user-writable path allows any user to replace the binary and gain code execution at next logon.'
                ))
                continue
            }

            # WREG-006: Unknown/non-standard entries in Run keys
            $standardRunEntries = @(
                '(?i)SecurityHealth', '(?i)iTunesHelper', '(?i)OneDrive',
                '(?i)Microsoft', '(?i)Windows', '(?i)VMware', '(?i)VBox',
                '(?i)Realtek', '(?i)Intel', '(?i)NVIDIA', '(?i)AMD',
                '(?i)Google', '(?i)Chrome', '(?i)Teams', '(?i)Zoom'
            )
            $isKnown = $false
            foreach ($knownPattern in $standardRunEntries) {
                if ($entry.Name -match $knownPattern -or $value -match $knownPattern) {
                    $isKnown = $true
                    break
                }
            }

            # Check if path is in standard Program Files
            if ($value -match '(?i)^"?[A-Z]:\\Program Files') {
                $isKnown = $true
            }

            if (-not $isKnown) {
                $findings.Add((New-Finding `
                    -Id 'WREG-006' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "Unknown Run key entry: $($entry.Name)" `
                    -Description "Registry Run key contains an entry that does not match known legitimate software. This may warrant investigation." `
                    -ArtifactPath $runKeysPath `
                    -Evidence @("Key: $($entry.Key)", "Name: $($entry.Name)", "Value: $value") `
                    -Recommendation 'Verify this Run key entry is legitimate. Check the digital signature of the referenced executable.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Unknown Run key entries may indicate unauthorized persistence mechanisms installed by malware or an attacker.'
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # WREG-002: Winlogon Shell and Userinit modifications
    # ----------------------------------------------------------------
    if (Test-Path $winlogonPath) {
        $winlogonEntries = Read-RegistryFile -Path $winlogonPath
        $totalPersistencePoints += $winlogonEntries.Count

        foreach ($entry in $winlogonEntries) {
            $name = $entry.Name
            $value = $entry.Value

            if ($name -match '(?i)^Shell$') {
                # Default Shell should be explorer.exe
                if ($value -notmatch '(?i)^\s*"?explorer\.exe"?\s*$') {
                    $findings.Add((New-Finding `
                        -Id 'WREG-002' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "Modified Winlogon Shell value" `
                        -Description "The Winlogon Shell registry value has been changed from the default 'explorer.exe' to '$value'. This is a common persistence technique." `
                        -ArtifactPath $winlogonPath `
                        -Evidence @("Key: $($entry.Key)", "Shell = $value", "Expected: explorer.exe") `
                        -Recommendation 'Reset the Winlogon Shell value to explorer.exe. Investigate the configured executable for malicious activity.' `
                        -MITRE 'T1547.004' `
                        -CVSSv3Score '8.6' `
                        -TechnicalImpact 'Modified Winlogon Shell executes an attacker-controlled binary instead of or alongside the Windows shell at every user logon.'
                    ))
                }
            }
            elseif ($name -match '(?i)^Userinit$') {
                # Default Userinit should be userinit.exe (possibly with comma)
                $cleanValue = $value.TrimEnd(',').Trim()
                if ($cleanValue -notmatch '(?i)^"?C:\\Windows\\system32\\userinit\.exe"?$' -and
                    $cleanValue -notmatch '(?i)^"?userinit\.exe"?$') {
                    $findings.Add((New-Finding `
                        -Id 'WREG-002' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "Modified Winlogon Userinit value" `
                        -Description "The Winlogon Userinit registry value has been changed from the default. Current value: '$value'. Additional executables may have been appended for persistence." `
                        -ArtifactPath $winlogonPath `
                        -Evidence @("Key: $($entry.Key)", "Userinit = $value", "Expected: C:\Windows\system32\userinit.exe,") `
                        -Recommendation 'Reset the Winlogon Userinit value to C:\Windows\system32\userinit.exe, (with trailing comma). Investigate any additional binaries.' `
                        -MITRE 'T1547.004' `
                        -CVSSv3Score '8.6' `
                        -TechnicalImpact 'Modified Userinit value causes additional executables to run during logon initialization, providing persistent code execution.'
                    ))
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # WREG-003: Image File Execution Options debugger (IFEO hijacking)
    # ----------------------------------------------------------------
    if (Test-Path $ifeoPath) {
        $ifeoEntries = Read-RegistryFile -Path $ifeoPath

        foreach ($entry in $ifeoEntries) {
            if ($entry.Name -match '(?i)^Debugger$' -and -not [string]::IsNullOrWhiteSpace($entry.Value)) {
                $totalPersistencePoints++
                $findings.Add((New-Finding `
                    -Id 'WREG-003' `
                    -Severity 'Critical' `
                    -Category $analyzerCategory `
                    -Title "IFEO debugger hijack detected: $($entry.Key)" `
                    -Description "An Image File Execution Options debugger value is set, which will redirect execution of the target program to the specified debugger. This is a known persistence and evasion technique." `
                    -ArtifactPath $ifeoPath `
                    -Evidence @("Key: $($entry.Key)", "Debugger = $($entry.Value)") `
                    -Recommendation 'Remove the IFEO Debugger value unless it is used for legitimate debugging. Investigate the debugger executable for malicious behavior.' `
                    -MITRE 'T1546.012' `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'IFEO debugger hijacking redirects execution of legitimate programs to attacker-controlled binaries, enabling persistent code execution and defense evasion.'
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # WREG-004: AppInit_DLLs configured
    # ----------------------------------------------------------------
    if (Test-Path $appinitPath) {
        $appinitEntries = Read-RegistryFile -Path $appinitPath

        foreach ($entry in $appinitEntries) {
            if ($entry.Name -match '(?i)^AppInit_DLLs$' -and -not [string]::IsNullOrWhiteSpace($entry.Value) -and $entry.Value.Trim() -ne '""' -and $entry.Value.Trim() -ne '') {
                $totalPersistencePoints++
                $findings.Add((New-Finding `
                    -Id 'WREG-004' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "AppInit_DLLs configured for DLL injection" `
                    -Description "The AppInit_DLLs registry value is set to '$($entry.Value)'. DLLs listed here are loaded into every process that loads user32.dll, providing a system-wide injection mechanism." `
                    -ArtifactPath $appinitPath `
                    -Evidence @("Key: $($entry.Key)", "AppInit_DLLs = $($entry.Value)") `
                    -Recommendation 'Remove AppInit_DLLs values and set LoadAppInit_DLLs to 0. Investigate the referenced DLLs for malicious content.' `
                    -MITRE 'T1546.010' `
                    -CVSSv3Score '8.6' `
                    -TechnicalImpact 'AppInit_DLLs enables system-wide DLL injection into every user32.dll-loading process, allowing persistent code execution and credential harvesting.'
                ))
            }
            elseif ($entry.Name -match '(?i)^LoadAppInit_DLLs$' -and $entry.Value -match '^\s*1\s*$') {
                $findings.Add((New-Finding `
                    -Id 'WREG-004' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "LoadAppInit_DLLs is enabled" `
                    -Description "The LoadAppInit_DLLs value is set to 1, enabling the AppInit_DLLs injection mechanism. Even if no DLLs are currently configured, this setting should be disabled." `
                    -ArtifactPath $appinitPath `
                    -Evidence @("Key: $($entry.Key)", "LoadAppInit_DLLs = $($entry.Value)") `
                    -Recommendation 'Set LoadAppInit_DLLs to 0 to disable the AppInit_DLLs mechanism.' `
                    -MITRE 'T1546.010' `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Enabled LoadAppInit_DLLs setting allows DLL injection if AppInit_DLLs values are later configured.'
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # WREG-005: Non-default BootExecute value
    # ----------------------------------------------------------------
    if (Test-Path $bootExecPath) {
        $bootEntries = Read-RegistryFile -Path $bootExecPath

        foreach ($entry in $bootEntries) {
            if ($entry.Name -match '(?i)^BootExecute$') {
                $value = $entry.Value.Trim()
                # Default is "autocheck autochk *"
                if ($value -ne 'autocheck autochk *' -and $value -ne '{autocheck autochk *}' -and
                    $value -notmatch '^\s*autocheck\s+autochk\s+\*\s*$') {
                    $totalPersistencePoints++
                    $findings.Add((New-Finding `
                        -Id 'WREG-005' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "Non-default BootExecute value detected" `
                        -Description "The BootExecute registry value has been modified from its default. Programs listed here run during the boot process before Windows fully loads, making this a powerful persistence mechanism." `
                        -ArtifactPath $bootExecPath `
                        -Evidence @("Key: $($entry.Key)", "BootExecute = $value", "Expected: autocheck autochk *") `
                        -Recommendation 'Reset BootExecute to the default value: autocheck autochk *. Investigate any non-default entries for malicious activity.' `
                        -MITRE 'T1547.001' `
                        -CVSSv3Score '8.6' `
                        -TechnicalImpact 'Modified BootExecute runs attacker code during early boot before security software loads, providing highly persistent and stealthy access.'
                    ))
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # WREG-008 (Informational): Registry persistence summary
    # ----------------------------------------------------------------
    $summaryEvidence = @(
        "Total persistence points examined: $totalPersistencePoints"
        "Run key entries: $($allRunKeyEntries.Count)"
    )

    if (Test-Path $winlogonPath) { $summaryEvidence += "Winlogon keys: Present" }
    else { $summaryEvidence += "Winlogon keys: Not collected" }

    if (Test-Path $ifeoPath) { $summaryEvidence += "IFEO keys: Present" }
    else { $summaryEvidence += "IFEO keys: Not collected" }

    if (Test-Path $appinitPath) { $summaryEvidence += "AppInit_DLLs keys: Present" }
    else { $summaryEvidence += "AppInit_DLLs keys: Not collected" }

    if (Test-Path $bootExecPath) { $summaryEvidence += "BootExecute keys: Present" }
    else { $summaryEvidence += "BootExecute keys: Not collected" }

    $findingCount = $findings.Count
    $summaryEvidence += "Security findings generated: $findingCount"

    $findings.Add((New-Finding `
        -Id 'WREG-008' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Registry persistence analysis summary' `
        -Description 'Summary of registry-based persistence mechanisms examined during analysis.' `
        -ArtifactPath $registryDir `
        -Evidence $summaryEvidence `
        -MITRE $mitrePersistence `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
