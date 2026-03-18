function Invoke-WinDefenderAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows Defender status, configuration, and threat detections.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ----------------------------------------------------------------
    # Parse Defender status (Get-MpComputerStatus output)
    # ----------------------------------------------------------------
    $defenderStatusPath = Join-Path $EvidencePath 'defender/defender_status.txt'
    $statusProps = @{}

    if (Test-Path $defenderStatusPath) {
        $statusLines = Read-ArtifactContent -Path $defenderStatusPath
        foreach ($line in $statusLines) {
            if ($line -match '^\s*(\S[\w\s]*\S)\s*:\s*(.+)$') {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                $statusProps[$key] = $value
            }
        }
    }

    # ----------------------------------------------------------------
    # Parse Defender preferences (Get-MpPreference output)
    # ----------------------------------------------------------------
    $defenderPrefsPath = Join-Path $EvidencePath 'defender/defender_preferences.txt'
    $prefsProps = @{}

    if (Test-Path $defenderPrefsPath) {
        $prefsLines = Read-ArtifactContent -Path $defenderPrefsPath
        foreach ($line in $prefsLines) {
            if ($line -match '^\s*(\S[\w\s]*\S)\s*:\s*(.*)$') {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                $prefsProps[$key] = $value
            }
        }
    }

    # Helper: check if a property indicates disabled state
    function Test-PropertyDisabled {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        return ($Value -match '(?i)^(false|0|disabled)$')
    }

    function Test-PropertyEnabled {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        return ($Value -match '(?i)^(true|1|enabled)$')
    }

    # ----------------------------------------------------------------
    # WDEF-001: Real-time protection disabled
    # ----------------------------------------------------------------
    $rtpDisabled = $false
    $rtpEvidence = @()

    # Check status output
    foreach ($key in @('RealTimeProtectionEnabled', 'AMServiceEnabled', 'RealTimeScanDirection')) {
        if ($statusProps.ContainsKey($key)) {
            if (Test-PropertyDisabled $statusProps[$key]) {
                $rtpDisabled = $true
                $rtpEvidence += "$key : $($statusProps[$key])"
            }
        }
    }

    # Check preferences for DisableRealtimeMonitoring = True
    if ($prefsProps.ContainsKey('DisableRealtimeMonitoring') -and (Test-PropertyEnabled $prefsProps['DisableRealtimeMonitoring'])) {
        $rtpDisabled = $true
        $rtpEvidence += "DisableRealtimeMonitoring : $($prefsProps['DisableRealtimeMonitoring'])"
    }

    if ($rtpDisabled) {
        $findings.Add((New-Finding -Id 'WDEF-001' -Severity 'Critical' -Category 'Defender' `
            -Title 'Windows Defender real-time protection is disabled' `
            -Description 'Real-time protection is disabled on this system. Without real-time scanning, malware can execute and persist without being detected or blocked.' `
            -ArtifactPath 'defender/defender_status.txt' `
            -Evidence $rtpEvidence `
            -Recommendation 'Enable real-time protection immediately: Set-MpPreference -DisableRealtimeMonitoring $false. Investigate why it was disabled.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '9.1' `
            -TechnicalImpact 'Without real-time protection, malware can execute freely without interception, enabling data theft, ransomware, and persistent access.'))
    }

    # ----------------------------------------------------------------
    # WDEF-002: Antivirus disabled entirely
    # ----------------------------------------------------------------
    $avDisabled = $false
    $avEvidence = @()

    foreach ($key in @('AntivirusEnabled', 'AntispywareEnabled', 'IsTamperProtected')) {
        if ($statusProps.ContainsKey($key) -and (Test-PropertyDisabled $statusProps[$key])) {
            $avDisabled = $true
            $avEvidence += "$key : $($statusProps[$key])"
        }
    }

    if ($prefsProps.ContainsKey('DisableAntiSpyware') -and (Test-PropertyEnabled $prefsProps['DisableAntiSpyware'])) {
        $avDisabled = $true
        $avEvidence += "DisableAntiSpyware : $($prefsProps['DisableAntiSpyware'])"
    }
    if ($prefsProps.ContainsKey('DisableAntiVirus') -and (Test-PropertyEnabled $prefsProps['DisableAntiVirus'])) {
        $avDisabled = $true
        $avEvidence += "DisableAntiVirus : $($prefsProps['DisableAntiVirus'])"
    }

    if ($avDisabled) {
        $findings.Add((New-Finding -Id 'WDEF-002' -Severity 'Critical' -Category 'Defender' `
            -Title 'Windows Defender antivirus components are disabled' `
            -Description 'One or more core Defender antivirus/antispyware components are disabled. The system has no active malware protection.' `
            -ArtifactPath 'defender/defender_status.txt' `
            -Evidence $avEvidence `
            -Recommendation 'Re-enable Defender immediately. Check for Group Policy or registry settings disabling Defender. Investigate potential tampering.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Completely disabled antivirus leaves the system fully exposed to malware, ransomware, and all forms of malicious software.'))
    }

    # ----------------------------------------------------------------
    # WDEF-003: Exclusion paths configured
    # ----------------------------------------------------------------
    $exclusionPaths = @()

    foreach ($key in @('ExclusionPath', 'ExclusionPaths')) {
        if ($prefsProps.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($prefsProps[$key])) {
            $val = $prefsProps[$key]
            if ($val -notmatch '^\s*(\{\}|$)') {
                # Split on common delimiters for list values
                $paths = $val -replace '[{}]', '' -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                $exclusionPaths += $paths
            }
        }
    }

    if ($exclusionPaths.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WDEF-003' -Severity 'High' -Category 'Defender' `
            -Title "Defender exclusion paths configured ($($exclusionPaths.Count) paths)" `
            -Description "Found $($exclusionPaths.Count) path exclusion(s) in Windows Defender. Attackers commonly add exclusion paths to hide malware from scanning." `
            -ArtifactPath 'defender/defender_preferences.txt' `
            -Evidence @($exclusionPaths | ForEach-Object { "ExclusionPath: $_" }) `
            -Recommendation 'Review all exclusion paths and remove any that are not required. Check if exclusions were added around the time of suspected compromise.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Exclusion paths create blind spots where malware can be stored and executed without being scanned by Defender.'))
    }

    # ----------------------------------------------------------------
    # WDEF-004: Exclusion processes configured
    # ----------------------------------------------------------------
    $exclusionProcesses = @()

    foreach ($key in @('ExclusionProcess', 'ExclusionProcesses')) {
        if ($prefsProps.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($prefsProps[$key])) {
            $val = $prefsProps[$key]
            if ($val -notmatch '^\s*(\{\}|$)') {
                $procs = $val -replace '[{}]', '' -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                $exclusionProcesses += $procs
            }
        }
    }

    if ($exclusionProcesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WDEF-004' -Severity 'High' -Category 'Defender' `
            -Title "Defender exclusion processes configured ($($exclusionProcesses.Count) processes)" `
            -Description "Found $($exclusionProcesses.Count) process exclusion(s) in Windows Defender. Excluded processes can execute malicious code without being scanned." `
            -ArtifactPath 'defender/defender_preferences.txt' `
            -Evidence @($exclusionProcesses | ForEach-Object { "ExclusionProcess: $_" }) `
            -Recommendation 'Review all process exclusions. Remove any that are not strictly necessary. Attackers may rename malware to match excluded process names.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Process exclusions allow specific executables to run without Defender scanning, enabling malware execution if the exclusion is exploited.'))
    }

    # ----------------------------------------------------------------
    # WDEF-005: Exclusion extensions configured
    # ----------------------------------------------------------------
    $exclusionExtensions = @()

    foreach ($key in @('ExclusionExtension', 'ExclusionExtensions')) {
        if ($prefsProps.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($prefsProps[$key])) {
            $val = $prefsProps[$key]
            if ($val -notmatch '^\s*(\{\}|$)') {
                $exts = $val -replace '[{}]', '' -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                $exclusionExtensions += $exts
            }
        }
    }

    if ($exclusionExtensions.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WDEF-005' -Severity 'High' -Category 'Defender' `
            -Title "Defender exclusion extensions configured ($($exclusionExtensions.Count) extensions)" `
            -Description "Found $($exclusionExtensions.Count) file extension exclusion(s) in Windows Defender. Files with excluded extensions are not scanned, creating potential blind spots." `
            -ArtifactPath 'defender/defender_preferences.txt' `
            -Evidence @($exclusionExtensions | ForEach-Object { "ExclusionExtension: $_" }) `
            -Recommendation 'Review all extension exclusions. Remove any that are not strictly required. Ensure common executable extensions are never excluded.' `
            -MITRE 'T1562.001' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Extension exclusions allow files with specific extensions to bypass scanning, enabling malware with matching extensions to evade detection.'))
    }

    # ----------------------------------------------------------------
    # WDEF-006: Recent threat detections found
    # ----------------------------------------------------------------
    $threatDetectionsPath = Join-Path $EvidencePath 'defender/threat_detections.csv'
    if (Test-Path $threatDetectionsPath) {
        try {
            $threats = Import-Csv -Path $threatDetectionsPath -ErrorAction Stop
            if ($threats.Count -gt 0) {
                $threatEvidence = @()
                foreach ($threat in $threats) {
                    $threatName = ''
                    $threatSeverity = ''
                    $threatResource = ''
                    $threatTime = ''

                    foreach ($field in @('ThreatName', 'InitialDetectionTime', 'Resources', 'ActionSuccess', 'Severity', 'DetectionTime')) {
                        # Normalize different CSV column names
                    }
                    if ($threat.PSObject.Properties['ThreatName']) { $threatName = $threat.ThreatName }
                    elseif ($threat.PSObject.Properties['Name']) { $threatName = $threat.Name }
                    elseif ($threat.PSObject.Properties['Threat']) { $threatName = $threat.Threat }

                    if ($threat.PSObject.Properties['InitialDetectionTime']) { $threatTime = $threat.InitialDetectionTime }
                    elseif ($threat.PSObject.Properties['DetectionTime']) { $threatTime = $threat.DetectionTime }
                    elseif ($threat.PSObject.Properties['TimeDetected']) { $threatTime = $threat.TimeDetected }

                    if ($threat.PSObject.Properties['Resources']) { $threatResource = $threat.Resources }
                    elseif ($threat.PSObject.Properties['Path']) { $threatResource = $threat.Path }
                    elseif ($threat.PSObject.Properties['FilePath']) { $threatResource = $threat.FilePath }

                    if ($threat.PSObject.Properties['Severity']) { $threatSeverity = $threat.Severity }
                    elseif ($threat.PSObject.Properties['SeverityID']) { $threatSeverity = $threat.SeverityID }

                    $entry = "Threat: $threatName"
                    if (-not [string]::IsNullOrWhiteSpace($threatSeverity)) { $entry += " [Severity=$threatSeverity]" }
                    if (-not [string]::IsNullOrWhiteSpace($threatTime)) { $entry += " at $threatTime" }
                    if (-not [string]::IsNullOrWhiteSpace($threatResource)) { $entry += " in $threatResource" }
                    $threatEvidence += $entry
                }

                $findings.Add((New-Finding -Id 'WDEF-006' -Severity 'Critical' -Category 'Defender' `
                    -Title "Recent threat detections found ($($threats.Count) threats)" `
                    -Description "Windows Defender has detected $($threats.Count) threat(s). These detections indicate malware or potentially unwanted software was found on the system." `
                    -ArtifactPath 'defender/threat_detections.csv' `
                    -Evidence @($threatEvidence | Select-Object -First 15) `
                    -Recommendation 'Review all threat detections. Ensure threats were quarantined or removed. Investigate the source of each threat and check for persistence mechanisms.' `
                    -MITRE 'T1204' `
                    -CVSSv3Score '9.1' `
                    -TechnicalImpact 'Detected threats indicate active or recent malware presence. Even quarantined threats suggest the system was exposed to malicious software.'))
            }
        }
        catch {
            Write-Verbose "Failed to parse threat_detections.csv: $_"
        }
    }

    # ----------------------------------------------------------------
    # WDEF-007: Signature definitions out of date (> 7 days)
    # ----------------------------------------------------------------
    $sigOutOfDate = $false
    $sigEvidence = @()
    $maxSigAgeDays = 7
    if ($Rules.ContainsKey('max_signature_age_days')) { $maxSigAgeDays = [int]$Rules['max_signature_age_days'] }

    # Check AntivirusSignatureLastUpdated or AntispywareSignatureLastUpdated
    foreach ($key in @('AntivirusSignatureLastUpdated', 'AntispywareSignatureLastUpdated', 'NISSignatureLastUpdated')) {
        if ($statusProps.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($statusProps[$key])) {
            try {
                $lastUpdated = [datetime]::Parse($statusProps[$key])
                $age = (Get-Date) - $lastUpdated
                if ($age.TotalDays -gt $maxSigAgeDays) {
                    $sigOutOfDate = $true
                    $sigEvidence += "$key : $($statusProps[$key]) (${([math]::Round($age.TotalDays, 1))} days ago)"
                }
                else {
                    $sigEvidence += "$key : $($statusProps[$key]) (${([math]::Round($age.TotalDays, 1))} days ago - OK)"
                }
            }
            catch {
                Write-Verbose "Could not parse date for $key : $($statusProps[$key])"
            }
        }
    }

    # Also check AntivirusSignatureAge if available (directly in days)
    if ($statusProps.ContainsKey('AntivirusSignatureAge')) {
        $sigAge = 0
        if ([int]::TryParse($statusProps['AntivirusSignatureAge'], [ref]$sigAge)) {
            if ($sigAge -gt $maxSigAgeDays) {
                $sigOutOfDate = $true
                $sigEvidence += "AntivirusSignatureAge : $sigAge days"
            }
        }
    }

    if ($sigOutOfDate) {
        $findings.Add((New-Finding -Id 'WDEF-007' -Severity 'Medium' -Category 'Defender' `
            -Title "Defender signature definitions are out of date (> $maxSigAgeDays days)" `
            -Description "Windows Defender signature definitions have not been updated in more than $maxSigAgeDays days. Outdated signatures cannot detect recently identified malware." `
            -ArtifactPath 'defender/defender_status.txt' `
            -Evidence $sigEvidence `
            -Recommendation "Update Defender signatures immediately: Update-MpSignature. Investigate why automatic updates are not working." `
            -MITRE 'T1562.001' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact "Outdated antivirus signatures miss detection of recently discovered malware families and variants."))
    }

    # ----------------------------------------------------------------
    # WDEF-008: Defender status summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()

    if ($statusProps.Count -gt 0) {
        $summaryKeys = @(
            'AMServiceEnabled', 'AntivirusEnabled', 'AntispywareEnabled',
            'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled',
            'IoavProtectionEnabled', 'NISEnabled', 'OnAccessProtectionEnabled',
            'IsTamperProtected', 'AntivirusSignatureVersion',
            'AntivirusSignatureLastUpdated', 'AntivirusSignatureAge',
            'FullScanAge', 'QuickScanAge', 'ComputerState'
        )
        foreach ($key in $summaryKeys) {
            if ($statusProps.ContainsKey($key)) {
                $summaryItems += "$key : $($statusProps[$key])"
            }
        }
    }
    else {
        $summaryItems += 'Defender status file not found or empty'
    }

    if ($prefsProps.Count -gt 0) {
        $summaryItems += "Defender preferences: $($prefsProps.Count) settings loaded"
    }
    else {
        $summaryItems += 'Defender preferences file not found or empty'
    }

    $summaryItems += "Exclusion paths: $($exclusionPaths.Count)"
    $summaryItems += "Exclusion processes: $($exclusionProcesses.Count)"
    $summaryItems += "Exclusion extensions: $($exclusionExtensions.Count)"

    if (Test-Path $threatDetectionsPath) {
        try {
            $threatCount = (Import-Csv -Path $threatDetectionsPath -ErrorAction Stop).Count
            $summaryItems += "Threat detections: $threatCount"
        }
        catch {
            $summaryItems += 'Threat detections: unable to parse'
        }
    }
    else {
        $summaryItems += 'Threat detections file not found'
    }

    $findings.Add((New-Finding -Id 'WDEF-008' -Severity 'Informational' -Category 'Defender' `
        -Title 'Windows Defender status summary' `
        -Description 'Summary of Windows Defender configuration, protection status, and threat detection findings.' `
        -ArtifactPath 'defender/defender_status.txt' `
        -Evidence $summaryItems `
        -Recommendation 'Review the Defender configuration summary and address any gaps in protection.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of Windows Defender security posture.'))

    return $findings.ToArray()
}
