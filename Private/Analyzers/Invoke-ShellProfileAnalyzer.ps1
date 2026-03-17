function Invoke-ShellProfileAnalyzer {
    <#
    .SYNOPSIS
        Analyzes shell profile and RC files for persistence mechanisms and suspicious modifications.
    .DESCRIPTION
        Examines system-wide and per-user shell profile files (.bashrc, .profile, .bash_profile, etc.)
        for download-and-execute patterns, alias hijacking, LD_PRELOAD injection, PATH manipulation,
        reverse shells, and base64 obfuscation.
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
    $analyzedFiles = [System.Collections.ArrayList]::new()
    $systemProfileContent = @{}  # Track system profile contents for comparison

    # System-wide profile files
    $systemProfiles = @(
        'etc/profile'
        'etc/bash.bashrc'
        'etc/bashrc'
    )

    # System profile directories
    $systemProfileDirs = @(
        'etc/profile.d'
    )

    # Per-user profile file names (relative to user home directory)
    $userProfileNames = @(
        '.bashrc'
        '.bash_profile'
        '.profile'
        '.bash_login'
        '.bash_logout'
    )

    # Root user profile files
    $rootProfiles = @(
        'root/.bashrc'
        'root/.profile'
        'root/.bash_profile'
    )

    # Detection patterns
    $downloadExecPattern = '(curl|wget)\s+[^|]*\|\s*(ba)?sh|(curl|wget)\s+.*-[oO]\s+\S+.*;\s*(chmod\s+.*;\s*)?(ba)?sh|(curl|wget)\s+[^|]*\|\s*python'

    $reverseShellPatterns = @(
        '/dev/tcp/'
        '/dev/udp/'
        'bash\s+-i\s+>&'
        'nc\s+.*-e\s+/bin/(ba)?sh'
        'ncat\s+.*-e\s+/bin/(ba)?sh'
        'mkfifo.*nc\s'
        'python.*socket.*connect'
        'perl.*socket.*INET'
        'ruby.*TCPSocket'
        'php.*fsockopen'
        'socat\s+.*exec'
        'telnet\s+.*\|\s*/bin/(ba)?sh'
        'exec\s+\d+<>/dev/tcp/'
        '0<&\d+-\s*;exec\s+\d+<>'
    )

    $base64Pattern = '(base64\s+-d|base64\s+--decode|\becho\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64|eval\s*.*\$\(.*base64|[A-Za-z0-9+/=]{40,})'

    # Sensitive commands that should not be aliased
    $sensitiveCommands = @('sudo', 'su', 'ssh', 'passwd', 'login', 'scp', 'sftp', 'gpg', 'openssl')

    # Suspicious PATH directories
    $suspiciousPathDirs = @('/tmp', '/dev/shm', '/var/tmp')

    # -------------------------------------------------------------------------
    # Helper: Analyze a single profile file
    # -------------------------------------------------------------------------
    function Analyze-ProfileFile {
        param(
            [string]$FilePath,
            [string]$LinuxPath,
            [bool]$IsSystemProfile = $false
        )

        $content = Read-ArtifactContent -Path $FilePath
        if ($content.Count -eq 0) { return }

        $null = $analyzedFiles.Add([PSCustomObject]@{
            LinuxPath     = $LinuxPath
            ResolvedPath  = $FilePath
            LineCount     = $content.Count
            IsSystem      = $IsSystemProfile
        })

        # Store system profile content for later comparison
        if ($IsSystemProfile) {
            $systemProfileContent[$LinuxPath] = $content
        }

        $lineNum = 0
        foreach ($rawLine in $content) {
            $lineNum++
            $line = $rawLine.Trim()

            # Skip empty lines and pure comments
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.StartsWith('#')) { continue }

            # Strip inline comments for analysis (but keep original for evidence)
            $activeLine = $line
            # Simple inline comment removal - be careful not to strip '#' inside quotes
            if ($activeLine -match '^([^#"'']*(?:"[^"]*"[^#"'']*|''[^'']*''[^#"'']*)*)#') {
                $activeLine = $Matches[1].Trim()
            }

            if ([string]::IsNullOrWhiteSpace($activeLine)) { continue }

            # PROF-001: Download-and-execute patterns
            if ($activeLine -match $downloadExecPattern) {
                $null = $findings.Add((New-Finding -Id 'PROF-001' -Severity 'Critical' `
                    -Category 'Persistence' `
                    -Title 'Download-and-execute pattern in shell profile' `
                    -Description "File '$LinuxPath' contains a download-and-execute pattern at line $lineNum. This is a strong indicator of compromise - content is fetched from the internet and executed directly." `
                    -ArtifactPath $FilePath `
                    -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine") `
                    -Recommendation 'Remove the malicious line immediately. Investigate the remote URL to understand the payload. Perform a full compromise assessment.' `
                    -MITRE 'T1546.004' `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'Allows remote code execution via automatic download and execution of attacker-controlled payloads on every shell login.'))
            }

            # PROF-002: Alias overrides for sensitive commands
            if ($activeLine -match '^\s*alias\s+(\w+)\s*=') {
                $aliasName = $Matches[1]
                if ($aliasName -in $sensitiveCommands) {
                    $null = $findings.Add((New-Finding -Id 'PROF-002' -Severity 'High' `
                        -Category 'Persistence' `
                        -Title "Alias override for security-sensitive command '$aliasName'" `
                        -Description "File '$LinuxPath' defines an alias for the security-sensitive command '$aliasName' at line $lineNum. This could be used to intercept credentials or modify command behavior." `
                        -ArtifactPath $FilePath `
                        -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine", "Aliased command: $aliasName") `
                        -Recommendation "Investigate the alias definition. Verify it is not capturing credentials or redirecting command execution. Remove if unauthorized." `
                        -MITRE 'T1546.004' `
                        -CVSSv3Score '7.8' `
                        -TechnicalImpact "Enables credential interception or command hijacking by replacing the security-sensitive '$aliasName' command with attacker-controlled behavior."))
                }
            }

            # PROF-003: LD_PRELOAD set in profile files
            if ($activeLine -match '(?:export\s+)?LD_PRELOAD\s*=') {
                $null = $findings.Add((New-Finding -Id 'PROF-003' -Severity 'High' `
                    -Category 'Persistence' `
                    -Title 'LD_PRELOAD set in shell profile' `
                    -Description "File '$LinuxPath' sets LD_PRELOAD at line $lineNum. This forces a shared library to be loaded before all others, which can be used to hijack function calls in any executed program." `
                    -ArtifactPath $FilePath `
                    -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine") `
                    -Recommendation 'Identify the preloaded library and analyze it for malicious behavior. Remove the LD_PRELOAD setting if unauthorized.' `
                    -MITRE 'T1574.006' `
                    -CVSSv3Score '8.4' `
                    -TechnicalImpact 'Allows arbitrary code execution by hijacking shared library function calls in every process launched from this shell environment.'))
            }

            # PROF-004: PATH manipulation with suspicious directories
            if ($activeLine -match '(?:export\s+)?PATH\s*=') {
                foreach ($susDir in $suspiciousPathDirs) {
                    if ($activeLine -match [regex]::Escape($susDir)) {
                        $null = $findings.Add((New-Finding -Id 'PROF-004' -Severity 'High' `
                            -Category 'Persistence' `
                            -Title "PATH manipulation: suspicious directory '$susDir' added" `
                            -Description "File '$LinuxPath' modifies PATH to include suspicious directory '$susDir' at line $lineNum. Placing malicious binaries in PATH-included writable directories enables command hijacking." `
                            -ArtifactPath $FilePath `
                            -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine", "Suspicious directory: $susDir") `
                            -Recommendation 'Remove the suspicious directory from PATH. Check the directory for malicious binaries masquerading as common commands.' `
                            -MITRE 'T1546.004' `
                            -CVSSv3Score '7.8' `
                            -TechnicalImpact "Enables command hijacking by placing malicious binaries in world-writable directory '$susDir' that is included in PATH."))
                        break
                    }
                }

                # Check for hidden directories in PATH (e.g., /home/user/.hidden/bin)
                if ($activeLine -match 'PATH.*(/[^:]*?/\.[^/:"'']+[^:"'']*)') {
                    $hiddenDir = $Matches[1]
                    $null = $findings.Add((New-Finding -Id 'PROF-004' -Severity 'High' `
                        -Category 'Persistence' `
                        -Title "PATH manipulation: hidden directory added" `
                        -Description "File '$LinuxPath' modifies PATH to include a hidden directory '$hiddenDir' at line $lineNum. Hidden directories in PATH are unusual and may contain malicious binaries." `
                        -ArtifactPath $FilePath `
                        -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine", "Hidden directory: $hiddenDir") `
                        -Recommendation 'Investigate the hidden directory and its contents. Remove from PATH if unauthorized.' `
                        -MITRE 'T1546.004' `
                        -CVSSv3Score '7.8' `
                        -TechnicalImpact 'Enables command hijacking by placing malicious binaries in a hidden directory added to PATH, evading casual inspection.'))
                }
            }

            # PROF-005: Reverse shell patterns or network connections
            foreach ($rsPattern in $reverseShellPatterns) {
                if ($activeLine -match $rsPattern) {
                    $null = $findings.Add((New-Finding -Id 'PROF-005' -Severity 'Medium' `
                        -Category 'Persistence' `
                        -Title 'Reverse shell or network connection in profile' `
                        -Description "File '$LinuxPath' contains a reverse shell or suspicious network connection pattern at line $lineNum." `
                        -ArtifactPath $FilePath `
                        -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine", "Matched pattern: $rsPattern") `
                        -Recommendation 'Remove the malicious code. Investigate the target IP/host for attribution. Assess full compromise scope.' `
                        -MITRE 'T1546.004' `
                        -CVSSv3Score '6.5' `
                        -TechnicalImpact 'May allow attacker to establish a reverse shell on every user login, enabling persistent remote access to the system.'))
                    break
                }
            }

            # PROF-006: Base64 encoded commands
            if ($activeLine -match $base64Pattern) {
                $null = $findings.Add((New-Finding -Id 'PROF-006' -Severity 'Medium' `
                    -Category 'Persistence' `
                    -Title 'Base64 encoded command in shell profile' `
                    -Description "File '$LinuxPath' contains base64 encoded content at line $lineNum. Encoding is commonly used to obfuscate malicious commands in profile files." `
                    -ArtifactPath $FilePath `
                    -Evidence @("File: $LinuxPath", "Line $lineNum`: $rawLine") `
                    -Recommendation 'Decode the base64 content and analyze the underlying command. Remove if malicious.' `
                    -MITRE 'T1546.004' `
                    -CVSSv3Score '6.5' `
                    -TechnicalImpact 'Obfuscated command execution on shell login may hide malicious payloads such as backdoors, credential theft, or data exfiltration.'))
            }
        }
    }

    # -------------------------------------------------------------------------
    # Process system-wide profile files
    # -------------------------------------------------------------------------
    foreach ($profileFile in $systemProfiles) {
        if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $profileFile) {
            $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $profileFile
            Write-Verbose "Analyzing system profile: $profileFile"
            Analyze-ProfileFile -FilePath $resolvedPath -LinuxPath $profileFile -IsSystemProfile $true
        }
    }

    # -------------------------------------------------------------------------
    # Process system profile directories (etc/profile.d/*)
    # -------------------------------------------------------------------------
    foreach ($profileDir in $systemProfileDirs) {
        $dirFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $profileDir
        foreach ($file in $dirFiles) {
            $linuxPath = "$profileDir/$($file.Name)"
            Write-Verbose "Analyzing system profile.d file: $linuxPath"
            Analyze-ProfileFile -FilePath $file.FullName -LinuxPath $linuxPath -IsSystemProfile $true
        }
    }

    # -------------------------------------------------------------------------
    # Process root user profile files
    # -------------------------------------------------------------------------
    foreach ($rootProfile in $rootProfiles) {
        if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $rootProfile) {
            $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $rootProfile
            Write-Verbose "Analyzing root profile: $rootProfile"
            Analyze-ProfileFile -FilePath $resolvedPath -LinuxPath $rootProfile -IsSystemProfile $false
        }
    }

    # -------------------------------------------------------------------------
    # Process user home directory profile files (home/*/.bashrc, etc.)
    # -------------------------------------------------------------------------
    $homeDir = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'home'
    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            foreach ($profileName in $userProfileNames) {
                $profilePath = Join-Path $userDir.FullName $profileName
                if (Test-Path $profilePath -PathType Leaf) {
                    $linuxPath = "home/$($userDir.Name)/$profileName"
                    Write-Verbose "Analyzing user profile: $linuxPath"
                    Analyze-ProfileFile -FilePath $profilePath -LinuxPath $linuxPath -IsSystemProfile $false
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # PROF-007: Informational summary
    # -------------------------------------------------------------------------
    $systemFiles = @($analyzedFiles | Where-Object { $_.IsSystem })
    $userFiles = @($analyzedFiles | Where-Object { -not $_.IsSystem })

    $summaryEvidence = @(
        "Total profile files analyzed: $($analyzedFiles.Count)"
        "System profile files: $($systemFiles.Count)"
        "User profile files: $($userFiles.Count)"
    )

    if ($systemFiles.Count -gt 0) {
        $summaryEvidence += "System profiles:"
        foreach ($f in $systemFiles) {
            $summaryEvidence += "  - $($f.LinuxPath) ($($f.LineCount) lines)"
        }
    }

    if ($userFiles.Count -gt 0) {
        $summaryEvidence += "User profiles:"
        foreach ($f in $userFiles) {
            $summaryEvidence += "  - $($f.LinuxPath) ($($f.LineCount) lines)"
        }
    }

    # Count findings by severity (excluding this summary)
    $criticalCount = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count

    $summaryEvidence += "Findings: $criticalCount Critical, $highCount High, $mediumCount Medium"

    $null = $findings.Add((New-Finding -Id 'PROF-007' -Severity 'Informational' `
        -Category 'Persistence' `
        -Title 'Shell profile analysis summary' `
        -Description "Analyzed $($analyzedFiles.Count) shell profile file(s): $($systemFiles.Count) system-wide and $($userFiles.Count) user-specific." `
        -Evidence $summaryEvidence `
        -MITRE 'T1546.004' `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    Write-Verbose "Shell profile analysis complete: $($findings.Count) finding(s) generated from $($analyzedFiles.Count) file(s)."

    return $findings.ToArray()
}
