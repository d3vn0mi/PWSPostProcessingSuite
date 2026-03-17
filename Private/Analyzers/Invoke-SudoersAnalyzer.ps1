function Invoke-SudoersAnalyzer {
    <#
    .SYNOPSIS
        Analyzes sudoers configuration for privilege escalation risks.
    .DESCRIPTION
        Examines /etc/sudoers and /etc/sudoers.d/* for dangerous rules including
        NOPASSWD ALL, ALL command grants, dangerous binary access, and insecure
        defaults directives.
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
    $analyzerCategory = 'Sudoers Configuration'
    $mitreSudo = 'T1548.003'

    # ----------------------------------------------------------------
    # Collect all sudoers content from main file and sudoers.d/
    # ----------------------------------------------------------------
    $sudoersFiles = [System.Collections.Generic.List[hashtable]]::new()

    # Main sudoers file
    $mainSudoersPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/sudoers'
    if (Test-Path $mainSudoersPath -PathType Leaf) {
        $sudoersFiles.Add(@{
            Path      = $mainSudoersPath
            LinuxPath = '/etc/sudoers'
            Lines     = @(Read-ArtifactContent -Path $mainSudoersPath)
        })
    }

    # sudoers.d/ drop-in files
    $sudoersDFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath 'etc/sudoers.d'
    foreach ($file in $sudoersDFiles) {
        $sudoersFiles.Add(@{
            Path      = $file.FullName
            LinuxPath = "/etc/sudoers.d/$($file.Name)"
            Lines     = @(Read-ArtifactContent -Path $file.FullName)
        })
    }

    if ($sudoersFiles.Count -eq 0) {
        Write-Verbose "SudoersAnalyzer: No sudoers files found, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Build dangerous binaries lookup from rules
    # ----------------------------------------------------------------
    $dangerousBinaries = @()
    if ($Rules.ContainsKey('dangerous_sudoers_binaries') -and $null -ne $Rules['dangerous_sudoers_binaries']) {
        $dangerousBinaries = @($Rules['dangerous_sudoers_binaries'])
    }

    # Also build a set of just the binary names for matching (e.g. "vim" from "/usr/bin/vim")
    $dangerousBinaryNames = @{}
    foreach ($bin in $dangerousBinaries) {
        $name = Split-Path $bin -Leaf
        $dangerousBinaryNames[$name] = $bin
        # Store full path too for direct matching
        $dangerousBinaryNames[$bin] = $bin
    }

    # ----------------------------------------------------------------
    # Tracking for summary
    # ----------------------------------------------------------------
    $totalRules = 0
    $includedFiles = [System.Collections.Generic.List[string]]::new()
    $allEffectiveLines = [System.Collections.Generic.List[string]]::new()

    # ----------------------------------------------------------------
    # Process each sudoers file
    # ----------------------------------------------------------------
    foreach ($sudoersFile in $sudoersFiles) {
        $filePath = $sudoersFile.Path
        $linuxPath = $sudoersFile.LinuxPath
        $lines = $sudoersFile.Lines

        foreach ($rawLine in $lines) {
            $line = $rawLine.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                # Check for #include and #includedir directives (these start with # but are not comments)
                if ($line -match '^#include\s+(.+)$') {
                    $includedFiles.Add($Matches[1])
                }
                elseif ($line -match '^#includedir\s+(.+)$') {
                    $includedFiles.Add("$($Matches[1])/*")
                }
                # Also handle @include / @includedir (newer sudoers syntax)
                continue
            }

            # Handle @include/@includedir (modern sudoers)
            if ($line -match '^@include\s+(.+)$') {
                $includedFiles.Add($Matches[1])
                continue
            }
            if ($line -match '^@includedir\s+(.+)$') {
                $includedFiles.Add("$($Matches[1])/*")
                continue
            }

            $totalRules++
            $allEffectiveLines.Add("[$linuxPath] $line")

            # ----------------------------------------------------------------
            # SUDO-001 (Critical): NOPASSWD: ALL rules
            # Matches lines like: user ALL=(ALL) NOPASSWD: ALL
            # ----------------------------------------------------------------
            if ($line -match 'NOPASSWD\s*:\s*ALL') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-001' `
                    -Severity 'Critical' `
                    -Category $analyzerCategory `
                    -Title "NOPASSWD ALL rule found in $linuxPath" `
                    -Description "A sudoers rule grants ALL commands without password authentication. This allows full privilege escalation without credential verification." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation 'Remove the NOPASSWD: ALL directive. If passwordless sudo is needed, restrict it to specific safe commands only.' `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'Enables privilege escalation from any local user to root without password authentication, allowing full system compromise.'
                ))
            }

            # ----------------------------------------------------------------
            # SUDO-002 (High): Rules granting ALL command access
            # Match lines where the command portion is ALL (but not NOPASSWD: ALL which is caught above)
            # Pattern: user/group HOST=(runas) [tags:] ALL
            # ----------------------------------------------------------------
            if ($line -notmatch 'NOPASSWD\s*:\s*ALL' -and $line -match '^\s*\S+\s+\S+\s*=\s*.*\)\s*(NOPASSWD\s*:\s*)?ALL\s*$') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-002' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "ALL command access granted in $linuxPath" `
                    -Description "A sudoers rule grants access to ALL commands. Even with password requirement, this allows full privilege escalation." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation 'Restrict sudo access to specific required commands instead of ALL. Follow the principle of least privilege.' `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '8.2' `
                    -TechnicalImpact 'Enables privilege escalation to root for the specified user or group, allowing full administrative control of the system.'
                ))
            }
            # Also catch simpler ALL patterns in the command list
            elseif ($line -notmatch 'NOPASSWD\s*:\s*ALL' -and $line -match '=\s*\(.*\)\s*ALL' -and $line -notmatch 'Defaults') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-002' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "ALL command access granted in $linuxPath" `
                    -Description "A sudoers rule grants access to ALL commands. Even with password requirement, this allows full privilege escalation." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation 'Restrict sudo access to specific required commands instead of ALL. Follow the principle of least privilege.' `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '8.2' `
                    -TechnicalImpact 'Enables privilege escalation to root for the specified user or group, allowing full administrative control of the system.'
                ))
            }

            # ----------------------------------------------------------------
            # SUDO-003 (High): Dangerous binaries in sudoers
            # Check if the line references any known dangerous binaries
            # ----------------------------------------------------------------
            if ($dangerousBinaries.Count -gt 0 -and $line -notmatch '^Defaults') {
                $matchedBinaries = [System.Collections.Generic.List[string]]::new()
                foreach ($bin in $dangerousBinaries) {
                    # Match full path or just the binary name in the command portion
                    $escapedBin = [regex]::Escape($bin)
                    $binName = Split-Path $bin -Leaf
                    $escapedName = [regex]::Escape($binName)

                    if ($line -match $escapedBin -or $line -match "(?<=[=/\s])$escapedName(?:\s|,|$)") {
                        $matchedBinaries.Add($bin)
                    }
                }

                foreach ($matchedBin in $matchedBinaries) {
                    $findings.Add((New-Finding `
                        -Id 'SUDO-003' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "Dangerous binary in sudoers: $matchedBin" `
                        -Description "Sudoers rule in $linuxPath grants access to '$matchedBin', which is a known GTFOBins binary that can be used for privilege escalation or command execution." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation "Remove sudo access to $matchedBin. This binary can be abused to escalate privileges, spawn shells, or read/write arbitrary files." `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '7.8' `
                        -TechnicalImpact "Allows privilege escalation to root via GTFOBins exploitation of '$matchedBin', enabling shell escape or arbitrary file read/write."
                    ))
                }
            }

            # ----------------------------------------------------------------
            # SUDO-004 (Medium): !authenticate or !requiretty
            # ----------------------------------------------------------------
            if ($line -match 'Defaults.*!authenticate') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-004' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "Authentication disabled via Defaults in $linuxPath" `
                    -Description "The '!authenticate' directive disables password prompts for sudo globally or for matched users, weakening access controls." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation 'Remove the !authenticate directive. Sudo should require password authentication.' `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '6.5' `
                    -TechnicalImpact 'Disables password authentication for sudo, allowing any user with sudo access to escalate privileges without credential verification.'
                ))
            }

            if ($line -match 'Defaults.*!requiretty') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-004' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "TTY requirement disabled via Defaults in $linuxPath" `
                    -Description "The '!requiretty' directive allows sudo to be run without a TTY. This can enable automated or remote privilege escalation without an interactive session." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation 'Remove the !requiretty directive unless specifically required for automation. Consider using Defaults requiretty.' `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Allows sudo execution without a TTY, enabling automated or remote privilege escalation from non-interactive sessions such as web shells.'
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # SUDO-005 (Informational): Full sudoers summary
    # ----------------------------------------------------------------
    $summaryEvidence = [System.Collections.Generic.List[string]]::new()
    $summaryEvidence.Add("Sudoers files analyzed: $($sudoersFiles.Count)")
    foreach ($sf in $sudoersFiles) {
        $summaryEvidence.Add("  - $($sf.LinuxPath) ($($sf.Lines.Count) lines)")
    }
    $summaryEvidence.Add("Total effective rules: $totalRules")
    if ($includedFiles.Count -gt 0) {
        $summaryEvidence.Add("Include directives found:")
        foreach ($inc in $includedFiles) {
            $summaryEvidence.Add("  - $inc")
        }
    }

    $findings.Add((New-Finding `
        -Id 'SUDO-005' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Sudoers configuration summary' `
        -Description 'Summary of sudoers configuration files analyzed and effective rules found.' `
        -ArtifactPath ($sudoersFiles[0].Path) `
        -Evidence @($summaryEvidence) `
        -MITRE $mitreSudo `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
