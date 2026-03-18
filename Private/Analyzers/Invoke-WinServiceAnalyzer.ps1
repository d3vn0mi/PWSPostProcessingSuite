function Invoke-WinServiceAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows services for security issues.
    .DESCRIPTION
        Examines collected Windows service data for misconfigurations including
        services with binaries in suspicious paths, unquoted service paths, services
        running as LocalSystem from writable locations, LOLBin usage, and non-Microsoft
        services running with elevated privileges.
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
    $analyzerCategory = 'Windows Services'
    $mitrePersistence = 'T1543.003'

    # ----------------------------------------------------------------
    # Load artifacts
    # ----------------------------------------------------------------
    $servicesDir = Join-Path $EvidencePath 'services'
    $commandsDir = Join-Path $EvidencePath 'collected_commands'

    $servicesCsvPath = Join-Path $servicesDir 'services_detailed.csv'
    $scQueryPath = Join-Path $commandsDir 'sc_query.txt'

    # Suspicious path patterns
    $suspiciousPaths = @(
        '(?i)\\Temp\\',
        '(?i)\\AppData\\',
        '(?i)\\Users\\Public\\',
        '(?i)\\ProgramData\\(?!Microsoft\\Windows Defender)',
        '(?i)\\Downloads\\',
        '(?i)\\Desktop\\',
        '(?i)\\Recycle',
        '(?i)\\Windows\\Temp\\'
    )

    # User-writable location patterns
    $writableLocations = @(
        '(?i)\\Users\\',
        '(?i)\\Temp\\',
        '(?i)\\tmp\\',
        '(?i)\\AppData\\',
        '(?i)\\ProgramData\\',
        '(?i)\\Public\\'
    )

    # LOLBin patterns
    $lolbinPatterns = @(
        '(?i)mshta\.exe',
        '(?i)regsvr32\.exe',
        '(?i)rundll32\.exe',
        '(?i)certutil\.exe',
        '(?i)bitsadmin\.exe',
        '(?i)wscript\.exe',
        '(?i)cscript\.exe',
        '(?i)msiexec\.exe',
        '(?i)installutil\.exe',
        '(?i)regasm\.exe',
        '(?i)regsvcs\.exe',
        '(?i)msconfig\.exe'
    )

    # ----------------------------------------------------------------
    # Parse services - try CSV first, then sc_query fallback
    # ----------------------------------------------------------------
    $services = [System.Collections.Generic.List[hashtable]]::new()

    if (Test-Path $servicesCsvPath) {
        try {
            $csvData = Import-Csv -Path $servicesCsvPath
            foreach ($row in $csvData) {
                $svc = @{
                    Name        = if ($row.Name) { $row.Name } else { '' }
                    DisplayName = if ($row.DisplayName) { $row.DisplayName } else { '' }
                    PathName    = if ($row.PathName) { $row.PathName } else { '' }
                    StartMode   = if ($row.StartMode) { $row.StartMode } else { '' }
                    State       = if ($row.State) { $row.State } else { '' }
                    StartName   = if ($row.StartName) { $row.StartName } else { '' }
                    RawLine     = ($row.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                }
                if (-not [string]::IsNullOrWhiteSpace($svc.Name)) {
                    $services.Add($svc)
                }
            }
        }
        catch {
            Write-Verbose "WinServiceAnalyzer: Failed to parse services CSV: $_"
        }
    }
    elseif (Test-Path $scQueryPath) {
        # Parse sc query output format
        $content = Get-Content -Path $scQueryPath -ErrorAction SilentlyContinue
        $currentSvc = $null
        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($currentSvc -and $currentSvc.Name) {
                    $services.Add($currentSvc)
                    $currentSvc = $null
                }
                continue
            }
            if ($trimmed -match '(?i)^SERVICE_NAME\s*[=:]\s*(.+)$') {
                if ($currentSvc -and $currentSvc.Name) { $services.Add($currentSvc) }
                $currentSvc = @{
                    Name = $Matches[1].Trim(); DisplayName = ''; PathName = ''
                    StartMode = ''; State = ''; StartName = ''; RawLine = $trimmed
                }
            }
            elseif ($currentSvc) {
                if ($trimmed -match '(?i)^DISPLAY_NAME\s*[=:]\s*(.+)$') {
                    $currentSvc.DisplayName = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^BINARY_PATH_NAME\s*[=:]\s*(.+)$') {
                    $currentSvc.PathName = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^START_TYPE\s*[=:]\s*(.+)$') {
                    $currentSvc.StartMode = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^STATE\s*[=:]\s*\d+\s+(.+)$') {
                    $currentSvc.State = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^SERVICE_START_NAME\s*[=:]\s*(.+)$') {
                    $currentSvc.StartName = $Matches[1].Trim()
                }
                $currentSvc.RawLine += "; $trimmed"
            }
        }
        if ($currentSvc -and $currentSvc.Name) { $services.Add($currentSvc) }
    }
    else {
        Write-Verbose "WinServiceAnalyzer: No service data found, skipping."
        return @()
    }

    if ($services.Count -eq 0) {
        Write-Verbose "WinServiceAnalyzer: No services parsed from evidence, skipping."
        return @()
    }

    $artifactPath = if (Test-Path $servicesCsvPath) { $servicesCsvPath } else { $scQueryPath }

    # Counters for summary
    $totalServices = $services.Count
    $autoStartServices = 0
    $localSystemServices = 0
    $stoppedAutoStart = [System.Collections.Generic.List[string]]::new()

    # ----------------------------------------------------------------
    # Analyze each service
    # ----------------------------------------------------------------
    foreach ($svc in $services) {
        $pathName = $svc.PathName
        $startName = $svc.StartName
        $name = $svc.Name
        $state = $svc.State
        $startMode = $svc.StartMode

        if ([string]::IsNullOrWhiteSpace($pathName)) { continue }

        # Track stats
        if ($startMode -match '(?i)(Auto|Automatic)') { $autoStartServices++ }
        if ($startName -match '(?i)(LocalSystem|Local System|SYSTEM)') { $localSystemServices++ }

        # Extract the actual binary path (handle quoted paths and arguments)
        $binaryPath = $pathName
        if ($binaryPath.StartsWith('"')) {
            $endQuote = $binaryPath.IndexOf('"', 1)
            if ($endQuote -gt 0) {
                $binaryPath = $binaryPath.Substring(1, $endQuote - 1)
            }
        }
        else {
            # Take path up to first space that looks like an argument separator
            $parts = $binaryPath -split '\s+'
            $binaryPath = $parts[0]
        }

        # ----------------------------------------------------------------
        # WSVC-001: Service binary in suspicious path
        # ----------------------------------------------------------------
        $isSuspiciousPath = $false
        foreach ($pattern in $suspiciousPaths) {
            if ($pathName -match $pattern) {
                $isSuspiciousPath = $true
                break
            }
        }

        if ($isSuspiciousPath) {
            $findings.Add((New-Finding `
                -Id 'WSVC-001' `
                -Severity 'Critical' `
                -Category $analyzerCategory `
                -Title "Service binary in suspicious path: $name" `
                -Description "Service '$name' ($($svc.DisplayName)) has its binary located in a suspicious path. Legitimate services typically reside in Program Files or System32." `
                -ArtifactPath $artifactPath `
                -Evidence @("Service: $name", "Binary: $pathName", "StartName: $startName", "State: $state") `
                -Recommendation 'Investigate this service immediately. Verify the binary is legitimate. Remove the service if it is malicious.' `
                -MITRE $mitrePersistence `
                -CVSSv3Score '9.8' `
                -TechnicalImpact 'Service with binary in suspicious location may indicate malware persistence. Services run with elevated privileges and start automatically.'
            ))
            continue
        }

        # ----------------------------------------------------------------
        # WSVC-002: Unquoted service path with spaces
        # ----------------------------------------------------------------
        if (-not $pathName.StartsWith('"') -and $pathName -match '\s' -and $pathName -match '\\[^\\]+\s[^\\]+\\') {
            $findings.Add((New-Finding `
                -Id 'WSVC-002' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title "Unquoted service path with spaces: $name" `
                -Description "Service '$name' has an unquoted path containing spaces. This is a classic privilege escalation vulnerability where an attacker can place a binary in a parent directory to hijack execution." `
                -ArtifactPath $artifactPath `
                -Evidence @("Service: $name", "Unquoted path: $pathName", "StartName: $startName") `
                -Recommendation "Quote the service binary path: sc config `"$name`" binPath= `"`"$pathName`"`"" `
                -MITRE 'T1574.009' `
                -CVSSv3Score '7.8' `
                -TechnicalImpact 'Unquoted service paths with spaces allow privilege escalation by placing a malicious executable in a parent directory along the path.'
            ))
        }

        # ----------------------------------------------------------------
        # WSVC-003: Service running as LocalSystem with binary in writable location
        # ----------------------------------------------------------------
        if ($startName -match '(?i)(LocalSystem|Local System|SYSTEM)') {
            $isWritable = $false
            foreach ($wPattern in $writableLocations) {
                if ($pathName -match $wPattern) {
                    $isWritable = $true
                    break
                }
            }

            if ($isWritable) {
                $findings.Add((New-Finding `
                    -Id 'WSVC-003' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "LocalSystem service in writable location: $name" `
                    -Description "Service '$name' runs as LocalSystem but its binary is in a user-writable location. An attacker could replace the binary to gain SYSTEM privileges." `
                    -ArtifactPath $artifactPath `
                    -Evidence @("Service: $name", "Binary: $pathName", "RunAs: $startName", "State: $state") `
                    -Recommendation 'Move the service binary to a protected location (Program Files or System32) and update the service path accordingly.' `
                    -MITRE 'T1574.010' `
                    -CVSSv3Score '8.6' `
                    -TechnicalImpact 'LocalSystem service with binary in writable path allows privilege escalation to SYSTEM by replacing the binary.'
                ))
            }
        }

        # ----------------------------------------------------------------
        # WSVC-004: Service using cmd.exe or powershell.exe
        # ----------------------------------------------------------------
        if ($pathName -match '(?i)(cmd\.exe|powershell\.exe|pwsh\.exe)') {
            $findings.Add((New-Finding `
                -Id 'WSVC-004' `
                -Severity 'Medium' `
                -Category $analyzerCategory `
                -Title "Service uses command interpreter: $name" `
                -Description "Service '$name' executes via cmd.exe or powershell.exe. This pattern is commonly seen in malicious services created by attackers for command execution." `
                -ArtifactPath $artifactPath `
                -Evidence @("Service: $name", "Binary: $pathName", "StartName: $startName") `
                -Recommendation 'Investigate why this service uses a command interpreter. Legitimate services typically have dedicated executables.' `
                -MITRE 'T1059.001' `
                -CVSSv3Score '6.5' `
                -TechnicalImpact 'Services executing through command interpreters may indicate post-exploitation persistence or living-off-the-land techniques.'
            ))
        }

        # ----------------------------------------------------------------
        # WSVC-005: Non-Microsoft service running as LocalSystem
        # ----------------------------------------------------------------
        if ($startName -match '(?i)(LocalSystem|Local System|SYSTEM)') {
            $isMicrosoft = $false
            # Check if the binary path is in Windows or Program Files\Microsoft or similar
            if ($pathName -match '(?i)\\Windows\\(System32|SysWOW64)\\' -or
                $pathName -match '(?i)\\Microsoft\\' -or
                $pathName -match '(?i)\\Windows Defender\\' -or
                $svc.DisplayName -match '(?i)Microsoft|Windows') {
                $isMicrosoft = $true
            }

            if (-not $isMicrosoft -and -not $isSuspiciousPath) {
                $findings.Add((New-Finding `
                    -Id 'WSVC-005' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "Non-Microsoft service running as LocalSystem: $name" `
                    -Description "Service '$name' ($($svc.DisplayName)) runs as LocalSystem but does not appear to be a Microsoft service. Third-party services should use least-privilege service accounts." `
                    -ArtifactPath $artifactPath `
                    -Evidence @("Service: $name", "DisplayName: $($svc.DisplayName)", "Binary: $pathName", "RunAs: $startName") `
                    -Recommendation 'Configure this service to run under a dedicated service account with minimal privileges instead of LocalSystem.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Non-Microsoft services running as LocalSystem have full system access. If compromised, an attacker gains SYSTEM-level privileges.'
                ))
            }
        }

        # ----------------------------------------------------------------
        # WSVC-006: Service binary path matches LOLBin patterns
        # ----------------------------------------------------------------
        $matchedLolbin = $null
        foreach ($lolbin in $lolbinPatterns) {
            if ($pathName -match $lolbin) {
                $matchedLolbin = $lolbin
                break
            }
        }

        if ($matchedLolbin) {
            $findings.Add((New-Finding `
                -Id 'WSVC-006' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title "Service uses LOLBin executable: $name" `
                -Description "Service '$name' uses a Living-off-the-Land Binary (LOLBin) as its executable. This is a common technique to abuse legitimate Windows tools for malicious purposes." `
                -ArtifactPath $artifactPath `
                -Evidence @("Service: $name", "Binary: $pathName", "Matched LOLBin: $matchedLolbin") `
                -Recommendation 'Investigate this service. LOLBin-based services are almost always malicious. Remove if not legitimate.' `
                -MITRE 'T1218' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact 'LOLBin-based services abuse trusted Windows binaries for malicious execution, bypassing application whitelisting and security controls.'
            ))
        }

        # ----------------------------------------------------------------
        # WSVC-007: Auto-start service that is stopped
        # ----------------------------------------------------------------
        if ($startMode -match '(?i)(Auto|Automatic)' -and $state -match '(?i)(Stopped|Stop)') {
            $stoppedAutoStart.Add($name)
        }
    }

    # Report stopped auto-start services as a group
    if ($stoppedAutoStart.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WSVC-007' `
            -Severity 'Low' `
            -Category $analyzerCategory `
            -Title "Auto-start services that are stopped ($($stoppedAutoStart.Count))" `
            -Description "Found $($stoppedAutoStart.Count) service(s) configured for automatic start that are currently stopped. This may indicate failed services or services stopped by an attacker." `
            -ArtifactPath $artifactPath `
            -Evidence @($stoppedAutoStart | ForEach-Object { "Stopped auto-start service: $_" }) `
            -Recommendation 'Review stopped auto-start services. Investigate why they are not running, especially security-related services.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '3.7' `
            -TechnicalImpact 'Stopped auto-start services may indicate tampering or failed security controls, reducing system protection.'
        ))
    }

    # ----------------------------------------------------------------
    # WSVC-008 (Informational): Service summary
    # ----------------------------------------------------------------
    $summaryEvidence = @(
        "Total services: $totalServices"
        "Auto-start services: $autoStartServices"
        "LocalSystem services: $localSystemServices"
        "Stopped auto-start services: $($stoppedAutoStart.Count)"
        "Security findings generated: $($findings.Count)"
    )

    $findings.Add((New-Finding `
        -Id 'WSVC-008' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Windows service analysis summary' `
        -Description 'Summary of Windows services examined during security analysis.' `
        -ArtifactPath $artifactPath `
        -Evidence $summaryEvidence `
        -MITRE $mitrePersistence `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
