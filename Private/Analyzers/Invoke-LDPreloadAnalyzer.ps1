function Invoke-LDPreloadAnalyzer {
    <#
    .SYNOPSIS
        Analyzes LD_PRELOAD and shared library configurations for hijacking indicators.
    .DESCRIPTION
        Examines /etc/ld.so.preload, /etc/ld.so.conf, /etc/ld.so.conf.d/*, and /etc/environment
        for evidence of LD_PRELOAD hijacking, suspicious library paths, and non-standard library
        directory configurations that could be used for shared library injection attacks.
    .PARAMETER EvidencePath
        Root path to the collected evidence/artifact directory.
    .PARAMETER Rules
        Hashtable containing detection rules and thresholds.
    .OUTPUTS
        Array of Finding objects created via New-Finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EvidencePath,

        [Parameter(Mandatory)]
        [hashtable]$Rules
    )

    $findings = [System.Collections.ArrayList]::new()
    $allLibraryPaths = [System.Collections.ArrayList]::new()
    $analyzedFiles = [System.Collections.ArrayList]::new()

    # Standard/whitelisted library paths
    $standardLibPaths = @(
        '/lib'
        '/lib64'
        '/usr/lib'
        '/usr/lib64'
        '/usr/local/lib'
        '/usr/local/lib64'
        '/usr/lib/x86_64-linux-gnu'
        '/usr/lib/aarch64-linux-gnu'
        '/usr/lib32'
        '/usr/libx32'
        '/lib/x86_64-linux-gnu'
        '/lib/aarch64-linux-gnu'
        '/lib/i386-linux-gnu'
        '/usr/lib/i386-linux-gnu'
    )

    # Suspicious path indicators
    $suspiciousDirs = @('/tmp', '/dev/shm', '/home', '/var/tmp')

    # -------------------------------------------------------------------------
    # LDPRE-001: Check /etc/ld.so.preload
    # -------------------------------------------------------------------------
    $ldPreloadFile = 'etc/ld.so.preload'
    if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $ldPreloadFile) {
        $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $ldPreloadFile
        $content = Read-ArtifactContent -Path $resolvedPath
        $null = $analyzedFiles.Add($ldPreloadFile)

        # Filter to non-empty, non-comment lines
        $activeEntries = @($content | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#')
        })

        if ($activeEntries.Count -gt 0) {
            $evidence = @(
                "File: /etc/ld.so.preload"
                "Entries found: $($activeEntries.Count)"
                "This file should normally be empty or nonexistent."
                "Libraries listed here are loaded into EVERY dynamically-linked process on the system."
                "Known rootkits using this technique: Jynx, Azazel, BEURK, vlany"
                "Entries:"
            )
            foreach ($entry in $activeEntries) {
                $evidence += "  - $($entry.Trim())"
            }

            $null = $findings.Add((New-Finding -Id 'LDPRE-001' -Severity 'Critical' `
                -Category 'Persistence' `
                -Title "ld.so.preload contains $($activeEntries.Count) librar$(if ($activeEntries.Count -eq 1) {'y'} else {'ies'}) - possible rootkit" `
                -Description "/etc/ld.so.preload contains active entries. This file forces shared libraries to be loaded before all others in every dynamically-linked process. This is a powerful persistence and rootkit technique. The file should normally be empty or nonexistent on production systems." `
                -ArtifactPath $resolvedPath `
                -Evidence $evidence `
                -Recommendation 'Immediately analyze the listed libraries with a malware analysis tool. Compare library hashes to known-good versions. Remove the entries and the malicious libraries. Investigate how they were placed and assess full compromise scope.' `
                -MITRE 'T1574.006' `
                -CVSSv3Score '9.8' `
                -TechnicalImpact "Malicious shared library injected into every process on the system, enabling credential theft, process hiding, and complete system compromise"))

            # Additionally flag entries pointing to suspicious locations
            foreach ($entry in $activeEntries) {
                $libPath = $entry.Trim()
                foreach ($susDir in $suspiciousDirs) {
                    if ($libPath -match "^$([regex]::Escape($susDir))(/|$)") {
                        $null = $findings.Add((New-Finding -Id 'LDPRE-001' -Severity 'Critical' `
                            -Category 'Persistence' `
                            -Title "ld.so.preload entry from suspicious path: $libPath" `
                            -Description "The ld.so.preload file references a library in '$susDir', a world-writable or user-controlled directory. This is extremely suspicious and likely malicious." `
                            -ArtifactPath $resolvedPath `
                            -Evidence @("File: /etc/ld.so.preload", "Entry: $libPath", "Suspicious base directory: $susDir") `
                            -Recommendation 'Remove the entry immediately. Analyze the library for malicious functionality. This is a high-confidence indicator of compromise.' `
                            -MITRE 'T1574.006' `
                            -CVSSv3Score '9.8' `
                            -TechnicalImpact "Rootkit library loaded from a world-writable directory into every process, enabling full system compromise and trivial re-infection"))
                        break
                    }
                }
            }
        }
        else {
            Write-Verbose "ld.so.preload exists but contains no active entries."
        }
    }
    else {
        Write-Verbose "ld.so.preload not found (expected - file normally does not exist)."
    }

    # -------------------------------------------------------------------------
    # LDPRE-002: Check /etc/environment for LD_PRELOAD
    # -------------------------------------------------------------------------
    $environmentFile = 'etc/environment'
    if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $environmentFile) {
        $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $environmentFile
        $content = Read-ArtifactContent -Path $resolvedPath
        $null = $analyzedFiles.Add($environmentFile)

        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            if ($trimmed -match '^\s*LD_PRELOAD\s*=') {
                $null = $findings.Add((New-Finding -Id 'LDPRE-002' -Severity 'High' `
                    -Category 'Persistence' `
                    -Title 'LD_PRELOAD set in /etc/environment' `
                    -Description "/etc/environment sets LD_PRELOAD at line $lineNum. This affects all PAM-based login sessions and forces a library to be loaded system-wide. This is a persistence technique used by rootkits." `
                    -ArtifactPath $resolvedPath `
                    -Evidence @("File: /etc/environment", "Line $lineNum`: $trimmed") `
                    -Recommendation 'Remove the LD_PRELOAD entry from /etc/environment. Analyze the referenced library for malicious behavior.' `
                    -MITRE 'T1574.006' `
                    -CVSSv3Score '8.4' `
                    -TechnicalImpact "Forces a malicious shared library into all PAM-based login sessions system-wide, enabling credential interception and persistent backdoor access"))
            }

            # Also check for LD_LIBRARY_PATH manipulation pointing to suspicious dirs
            if ($trimmed -match '^\s*LD_LIBRARY_PATH\s*=') {
                if ($trimmed -match '=\s*(.+)$') {
                    $pathValue = $Matches[1].Trim('"', "'")
                    $paths = $pathValue -split ':'
                    foreach ($p in $paths) {
                        $p = $p.Trim()
                        foreach ($susDir in $suspiciousDirs) {
                            if ($p -match "^$([regex]::Escape($susDir))(/|$)") {
                                $null = $findings.Add((New-Finding -Id 'LDPRE-003' -Severity 'High' `
                                    -Category 'Persistence' `
                                    -Title "Suspicious LD_LIBRARY_PATH in /etc/environment: $p" `
                                    -Description "/etc/environment configures LD_LIBRARY_PATH to include suspicious directory '$p'. This can be used to load malicious shared libraries system-wide." `
                                    -ArtifactPath $resolvedPath `
                                    -Evidence @("File: /etc/environment", "Line $lineNum`: $trimmed", "Suspicious path: $p") `
                                    -Recommendation 'Remove the suspicious path from LD_LIBRARY_PATH. Investigate the directory for malicious libraries.' `
                                    -MITRE 'T1574.006' `
                                    -CVSSv3Score '8.4' `
                                    -TechnicalImpact "Allows attacker-controlled shared libraries to be loaded system-wide via LD_LIBRARY_PATH pointing to a world-writable directory"))
                                break
                            }
                        }
                    }
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # LDPRE-002: Also check profile files for LD_PRELOAD
    # -------------------------------------------------------------------------
    $profileFilesForLdCheck = @(
        'etc/profile'
        'etc/bash.bashrc'
        'etc/bashrc'
    )

    foreach ($profileFile in $profileFilesForLdCheck) {
        if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $profileFile) {
            $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $profileFile
            $content = Read-ArtifactContent -Path $resolvedPath

            if ($profileFile -notin ($analyzedFiles | ForEach-Object { $_ })) {
                $null = $analyzedFiles.Add($profileFile)
            }

            $lineNum = 0
            foreach ($line in $content) {
                $lineNum++
                $trimmed = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

                if ($trimmed -match '(?:export\s+)?LD_PRELOAD\s*=') {
                    $null = $findings.Add((New-Finding -Id 'LDPRE-002' -Severity 'High' `
                        -Category 'Persistence' `
                        -Title "LD_PRELOAD set in profile file /$profileFile" `
                        -Description "Profile file '/$profileFile' sets LD_PRELOAD at line $lineNum. This forces a shared library to be loaded for all users who source this profile." `
                        -ArtifactPath $resolvedPath `
                        -Evidence @("File: /$profileFile", "Line $lineNum`: $trimmed") `
                        -Recommendation 'Remove the LD_PRELOAD setting. Analyze the referenced library for malicious behavior.' `
                        -MITRE 'T1574.006' `
                        -CVSSv3Score '8.4' `
                        -TechnicalImpact "Forces a malicious shared library into all user sessions sourcing this profile, enabling credential interception and persistent access"))
                }
            }
        }
    }

    # Check etc/profile.d/ for LD_PRELOAD
    $profileDirFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath 'etc/profile.d'
    foreach ($file in $profileDirFiles) {
        $linuxPath = "etc/profile.d/$($file.Name)"
        $content = Read-ArtifactContent -Path $file.FullName

        if ($linuxPath -notin ($analyzedFiles | ForEach-Object { $_ })) {
            $null = $analyzedFiles.Add($linuxPath)
        }

        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            if ($trimmed -match '(?:export\s+)?LD_PRELOAD\s*=') {
                $null = $findings.Add((New-Finding -Id 'LDPRE-002' -Severity 'High' `
                    -Category 'Persistence' `
                    -Title "LD_PRELOAD set in profile.d file /$linuxPath" `
                    -Description "Profile file '/$linuxPath' sets LD_PRELOAD at line $lineNum. This forces a shared library to be loaded for all users who source this profile." `
                    -ArtifactPath $file.FullName `
                    -Evidence @("File: /$linuxPath", "Line $lineNum`: $trimmed") `
                    -Recommendation 'Remove the LD_PRELOAD setting. Analyze the referenced library for malicious behavior.' `
                    -MITRE 'T1574.006' `
                    -CVSSv3Score '8.4' `
                    -TechnicalImpact "Forces a malicious shared library into all user sessions via profile.d, enabling credential interception and persistent access"))
            }
        }
    }

    # -------------------------------------------------------------------------
    # LDPRE-003 / LDPRE-004: Analyze ld.so.conf and ld.so.conf.d/*
    # -------------------------------------------------------------------------
    $ldConfFiles = [System.Collections.ArrayList]::new()

    # Main ld.so.conf
    $ldSoConf = 'etc/ld.so.conf'
    if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $ldSoConf) {
        $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $ldSoConf
        $null = $ldConfFiles.Add([PSCustomObject]@{
            LinuxPath    = $ldSoConf
            ResolvedPath = $resolvedPath
        })
        $null = $analyzedFiles.Add($ldSoConf)
    }

    # ld.so.conf.d/ directory files
    $confDirFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath 'etc/ld.so.conf.d'
    foreach ($file in $confDirFiles) {
        $linuxPath = "etc/ld.so.conf.d/$($file.Name)"
        $null = $ldConfFiles.Add([PSCustomObject]@{
            LinuxPath    = $linuxPath
            ResolvedPath = $file.FullName
        })
        $null = $analyzedFiles.Add($linuxPath)
    }

    foreach ($confFile in $ldConfFiles) {
        $content = Read-ArtifactContent -Path $confFile.ResolvedPath
        if ($content.Count -eq 0) { continue }

        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            $trimmed = $line.Trim()

            # Skip comments, empty lines, and include directives
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($trimmed.StartsWith('#')) { continue }
            if ($trimmed -match '^include\s') { continue }

            # This line should be a library path
            $libPath = $trimmed

            # Track all library paths for summary
            $null = $allLibraryPaths.Add([PSCustomObject]@{
                Path       = $libPath
                SourceFile = $confFile.LinuxPath
            })

            # LDPRE-003: Check for suspicious library paths
            $isSuspicious = $false
            foreach ($susDir in $suspiciousDirs) {
                if ($libPath -match "^$([regex]::Escape($susDir))(/|$)") {
                    $null = $findings.Add((New-Finding -Id 'LDPRE-003' -Severity 'High' `
                        -Category 'Persistence' `
                        -Title "Suspicious library path in /$($confFile.LinuxPath): $libPath" `
                        -Description "Library configuration file '/$($confFile.LinuxPath)' includes path '$libPath' at line $lineNum. This directory ($susDir) is world-writable or user-controlled, making it a target for shared library injection." `
                        -ArtifactPath $confFile.ResolvedPath `
                        -Evidence @("File: /$($confFile.LinuxPath)", "Line $lineNum`: $trimmed", "Suspicious base directory: $susDir") `
                        -Recommendation 'Remove the suspicious library path. Investigate the directory for malicious shared libraries. Run ldconfig after removing the entry.' `
                        -MITRE 'T1574.006' `
                        -CVSSv3Score '8.4' `
                        -TechnicalImpact "Allows shared library injection from a world-writable directory, enabling attacker to hijack any dynamically-linked application on the system"))
                    $isSuspicious = $true
                    break
                }
            }

            # Check for hidden directories in library path
            if (-not $isSuspicious -and $libPath -match '/\.[^/]+') {
                $null = $findings.Add((New-Finding -Id 'LDPRE-003' -Severity 'High' `
                    -Category 'Persistence' `
                    -Title "Hidden directory in library path: $libPath" `
                    -Description "Library configuration file '/$($confFile.LinuxPath)' includes a hidden directory in path '$libPath' at line $lineNum. Hidden directories in library paths are highly suspicious." `
                    -ArtifactPath $confFile.ResolvedPath `
                    -Evidence @("File: /$($confFile.LinuxPath)", "Line $lineNum`: $trimmed") `
                    -Recommendation 'Investigate the hidden directory and its contents. Remove the library path entry if unauthorized.' `
                    -MITRE 'T1574.006' `
                    -CVSSv3Score '8.4' `
                    -TechnicalImpact "Hidden directory in library search path enables stealthy shared library injection, allowing attacker to hijack system applications"))
                $isSuspicious = $true
            }

            # LDPRE-004: Non-standard library paths
            if (-not $isSuspicious) {
                $isStandard = $false
                foreach ($stdPath in $standardLibPaths) {
                    if ($libPath -eq $stdPath -or $libPath -match "^$([regex]::Escape($stdPath))(/|$)") {
                        $isStandard = $true
                        break
                    }
                }

                # Also allow common distro-specific paths under /usr/lib, /lib, /opt
                if (-not $isStandard -and $libPath -match '^/(usr/(lib|share)|lib|opt)/') {
                    $isStandard = $true
                }

                if (-not $isStandard) {
                    $null = $findings.Add((New-Finding -Id 'LDPRE-004' -Severity 'Medium' `
                        -Category 'Configuration' `
                        -Title "Non-standard library path: $libPath" `
                        -Description "Library configuration file '/$($confFile.LinuxPath)' includes non-standard path '$libPath' at line $lineNum. While this may be legitimate (e.g., third-party software), it should be verified against the system baseline." `
                        -ArtifactPath $confFile.ResolvedPath `
                        -Evidence @("File: /$($confFile.LinuxPath)", "Line $lineNum`: $trimmed", "Standard paths: $($standardLibPaths -join ', ')") `
                        -Recommendation 'Verify the library path belongs to legitimate software. Document the purpose if valid.' `
                        -MITRE 'T1574.006' `
                        -CVSSv3Score '4.7' `
                        -TechnicalImpact "Non-standard library search path could be leveraged for shared library injection if the directory has weak permissions"))
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # LDPRE-005: Summary of configured library paths
    # -------------------------------------------------------------------------
    $summaryEvidence = @(
        "Files analyzed: $($analyzedFiles.Count)"
    )

    foreach ($f in $analyzedFiles) {
        $summaryEvidence += "  - /$f"
    }

    $summaryEvidence += "Total configured library paths: $($allLibraryPaths.Count)"

    if ($allLibraryPaths.Count -gt 0) {
        $summaryEvidence += "Library paths:"
        $groupedPaths = $allLibraryPaths | Group-Object -Property SourceFile
        foreach ($group in $groupedPaths) {
            $summaryEvidence += "  From /$($group.Name):"
            foreach ($entry in $group.Group) {
                $isStd = $false
                foreach ($stdPath in $standardLibPaths) {
                    if ($entry.Path -eq $stdPath -or $entry.Path -match "^$([regex]::Escape($stdPath))(/|$)") {
                        $isStd = $true
                        break
                    }
                }
                $marker = if ($isStd) { '[standard]' } else { '[non-standard]' }
                $summaryEvidence += "    - $($entry.Path) $marker"
            }
        }
    }

    # Count findings by severity (excluding this summary)
    $criticalCount = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count

    $summaryEvidence += "Findings: $criticalCount Critical, $highCount High, $mediumCount Medium"

    $ldPreloadExists = Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath 'etc/ld.so.preload'
    $summaryEvidence += "ld.so.preload exists: $ldPreloadExists"

    $null = $findings.Add((New-Finding -Id 'LDPRE-005' -Severity 'Informational' `
        -Category 'Configuration' `
        -Title 'Shared library configuration analysis summary' `
        -Description "Analyzed $($analyzedFiles.Count) library configuration file(s) with $($allLibraryPaths.Count) configured library path(s)." `
        -Evidence $summaryEvidence `
        -MITRE 'T1574.006' `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    Write-Verbose "LD_PRELOAD analysis complete: $($findings.Count) finding(s) generated."

    return $findings.ToArray()
}
