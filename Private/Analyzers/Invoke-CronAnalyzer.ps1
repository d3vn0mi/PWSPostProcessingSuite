function Invoke-CronAnalyzer {
    <#
    .SYNOPSIS
        Analyzes cron job configurations for persistence and suspicious activity.
    .DESCRIPTION
        Examines system and user crontabs, cron directories, and referenced scripts
        for indicators of compromise including reverse shells, encoded commands,
        download-and-execute patterns, and execution from suspicious paths.
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
    $allCronJobs = [System.Collections.ArrayList]::new()
    $analyzedFiles = [System.Collections.ArrayList]::new()

    # Define all cron artifact locations
    $cronFiles = @(
        'etc/crontab'
    )

    $cronDirs = @(
        'etc/cron.d'
        'etc/cron.daily'
        'etc/cron.hourly'
        'etc/cron.weekly'
        'etc/cron.monthly'
        'var/spool/cron/crontabs'
    )

    # Suspicious execution paths
    $suspiciousPaths = @('/tmp/', '/dev/shm/', '/var/tmp/')

    # Reverse shell indicators from rules, with fallback defaults
    $reverseShellPatterns = @()
    if ($Rules.persistence_paths -and $Rules.persistence_paths.suspicious_cron_indicators) {
        $reverseShellPatterns = $Rules.persistence_paths.suspicious_cron_indicators
    }

    # Fallback built-in reverse shell regex patterns if rules don't provide them
    $builtinReverseShellRegex = @(
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
        'openssl\s+s_client'
        'awk.*\|getline'
    )

    # Base64 detection pattern
    $base64Pattern = '(base64\s+-d|base64\s+--decode|\becho\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64|[A-Za-z0-9+/=]{40,})'

    # Download-and-execute pattern
    $downloadExecPattern = '(wget|curl)\s+.*\|\s*(ba)?sh|(wget|curl)\s+.*-[oO]\s+\S+.*;\s*(ba)?sh|wget\s+.*&&\s*(ba)?sh|curl\s+.*&&\s*(ba)?sh'

    # -------------------------------------------------------------------------
    # Helper: Parse a cron line and return a structured object
    # -------------------------------------------------------------------------
    function Parse-CronLine {
        param(
            [string]$Line,
            [string]$SourceFile,
            [bool]$IsSystemCrontab = $false
        )

        $trimmed = $Line.Trim()

        # Skip empty lines, comments, and variable assignments
        if ([string]::IsNullOrWhiteSpace($trimmed)) { return $null }
        if ($trimmed.StartsWith('#')) { return $null }
        if ($trimmed -match '^\s*\w+=') { return $null }

        # System crontab format: min hour dom mon dow user command
        # User crontab format:   min hour dom mon dow command
        # Also handle @reboot, @daily, etc.
        $user = ''
        $command = ''
        $schedule = ''

        if ($trimmed -match '^@(reboot|yearly|annually|monthly|weekly|daily|hourly|midnight)\s+(.+)$') {
            $schedule = "@$($Matches[1])"
            $rest = $Matches[2]
            if ($IsSystemCrontab) {
                # First token after schedule is the user
                $parts = $rest -split '\s+', 2
                if ($parts.Count -ge 2) {
                    $user = $parts[0]
                    $command = $parts[1]
                }
                else {
                    $command = $rest
                }
            }
            else {
                $command = $rest
            }
        }
        elseif ($trimmed -match '^([\d\*,/\-]+\s+[\d\*,/\-]+\s+[\d\*,/\-]+\s+[\d\*,/\-]+\s+[\d\*,/\-]+)\s+(.+)$') {
            $schedule = $Matches[1]
            $rest = $Matches[2]
            if ($IsSystemCrontab) {
                $parts = $rest -split '\s+', 2
                if ($parts.Count -ge 2) {
                    $user = $parts[0]
                    $command = $parts[1]
                }
                else {
                    $command = $rest
                }
            }
            else {
                $command = $rest
            }
        }
        else {
            # Could not parse as cron format - skip
            return $null
        }

        return [PSCustomObject]@{
            Schedule   = $schedule
            User       = $user
            Command    = $command.Trim()
            SourceFile = $SourceFile
            RawLine    = $trimmed
        }
    }

    # -------------------------------------------------------------------------
    # Helper: Analyze a single cron job entry for suspicious indicators
    # -------------------------------------------------------------------------
    function Analyze-CronEntry {
        param(
            [PSCustomObject]$Entry
        )

        $cmd = $Entry.Command
        $source = $Entry.SourceFile

        # CRON-001: Reverse shell patterns
        # Check against rules-provided indicators
        if ($reverseShellPatterns.Count -gt 0) {
            $matchResult = Test-PatternMatch -InputText $cmd -Patterns $reverseShellPatterns
            if ($matchResult.Matched) {
                $null = $findings.Add((New-Finding -Id 'CRON-001' -Severity 'Critical' `
                    -Category 'Persistence' `
                    -Title 'Reverse shell pattern detected in cron job' `
                    -Description "Cron job contains a reverse shell indicator matching rule pattern '$($matchResult.Pattern)' in file '$source'." `
                    -ArtifactPath $source `
                    -Evidence @("Schedule: $($Entry.Schedule)", "User: $($Entry.User)", "Command: $cmd", "Matched pattern: $($matchResult.Pattern)") `
                    -Recommendation 'Immediately investigate the cron entry. Remove the malicious cron job and perform a full compromise assessment.' `
                    -MITRE 'T1053.003'))
            }
        }

        # Also check built-in reverse shell regex patterns
        foreach ($rsPattern in $builtinReverseShellRegex) {
            if ($cmd -match $rsPattern) {
                # Avoid duplicate if already caught by rules
                $isDuplicate = $false
                foreach ($f in $findings) {
                    if ($f.Id -eq 'CRON-001' -and $f.ArtifactPath -eq $source -and $f.Evidence -contains "Command: $cmd") {
                        $isDuplicate = $true
                        break
                    }
                }
                if (-not $isDuplicate) {
                    $null = $findings.Add((New-Finding -Id 'CRON-001' -Severity 'Critical' `
                        -Category 'Persistence' `
                        -Title 'Reverse shell pattern detected in cron job' `
                        -Description "Cron job contains a reverse shell indicator matching pattern '$rsPattern' in file '$source'." `
                        -ArtifactPath $source `
                        -Evidence @("Schedule: $($Entry.Schedule)", "User: $($Entry.User)", "Command: $cmd", "Matched pattern: $rsPattern") `
                        -Recommendation 'Immediately investigate the cron entry. Remove the malicious cron job and perform a full compromise assessment.' `
                        -MITRE 'T1053.003'))
                }
                break
            }
        }

        # CRON-002: Execution from suspicious paths
        foreach ($susPath in $suspiciousPaths) {
            if ($cmd -match [regex]::Escape($susPath)) {
                $null = $findings.Add((New-Finding -Id 'CRON-002' -Severity 'High' `
                    -Category 'Persistence' `
                    -Title 'Cron job executing from suspicious path' `
                    -Description "Cron job references suspicious path '$susPath' in file '$source'. Temporary directories are commonly used by attackers to stage malicious scripts." `
                    -ArtifactPath $source `
                    -Evidence @("Schedule: $($Entry.Schedule)", "User: $($Entry.User)", "Command: $cmd", "Suspicious path: $susPath") `
                    -Recommendation 'Investigate the referenced file and the cron entry. Verify the purpose and legitimacy of the scheduled task.' `
                    -MITRE 'T1053.003'))
                break
            }
        }

        # CRON-003: Base64 encoded commands
        if ($cmd -match $base64Pattern) {
            $null = $findings.Add((New-Finding -Id 'CRON-003' -Severity 'High' `
                -Category 'Persistence' `
                -Title 'Cron job contains base64 encoded command' `
                -Description "Cron job in '$source' uses base64 encoding which may be used to obfuscate malicious commands." `
                -ArtifactPath $source `
                -Evidence @("Schedule: $($Entry.Schedule)", "User: $($Entry.User)", "Command: $cmd") `
                -Recommendation 'Decode the base64 content and analyze the underlying command. Remove if malicious.' `
                -MITRE 'T1053.003'))
        }

        # CRON-004: Download and execute
        if ($cmd -match $downloadExecPattern) {
            $null = $findings.Add((New-Finding -Id 'CRON-004' -Severity 'High' `
                -Category 'Persistence' `
                -Title 'Cron job downloads and executes remote content' `
                -Description "Cron job in '$source' downloads content from the internet and pipes it to a shell for execution. This is a common attack pattern." `
                -ArtifactPath $source `
                -Evidence @("Schedule: $($Entry.Schedule)", "User: $($Entry.User)", "Command: $cmd") `
                -Recommendation 'Identify the remote URL, analyze what is being downloaded, and remove the malicious cron entry.' `
                -MITRE 'T1053.003'))
        }

        # CRON-005: Root execution from user-writable directories
        $isRoot = ($Entry.User -eq 'root' -or $source -match 'crontab$' -or $source -match 'cron\.(daily|hourly|weekly|monthly)')
        if ($isRoot) {
            foreach ($susPath in $suspiciousPaths) {
                if ($cmd -match [regex]::Escape($susPath)) {
                    $null = $findings.Add((New-Finding -Id 'CRON-005' -Severity 'Medium' `
                        -Category 'Persistence' `
                        -Title 'Root cron job executes from user-writable directory' `
                        -Description "A cron job running as root references a user-writable directory '$susPath' in file '$source'. This could allow privilege escalation if the referenced file is modified." `
                        -ArtifactPath $source `
                        -Evidence @("Schedule: $($Entry.Schedule)", "User: $($Entry.User)", "Command: $cmd", "Writable path: $susPath") `
                        -Recommendation 'Move the script to a root-owned directory with restricted permissions, or remove the cron job if unnecessary.' `
                        -MITRE 'T1053.003'))
                    break
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # Helper: Check content of scripts referenced in cron commands
    # -------------------------------------------------------------------------
    function Check-ReferencedScript {
        param(
            [PSCustomObject]$Entry
        )

        # Extract potential file paths from the command
        $cmd = $Entry.Command
        $potentialPaths = @()

        # Match absolute paths in the command
        $pathMatches = [regex]::Matches($cmd, '(/[a-zA-Z0-9_./-]+)')
        foreach ($m in $pathMatches) {
            $p = $m.Value
            # Only consider paths that look like scripts
            if ($p -match '\.(sh|bash|pl|py|rb|php)$' -or $p -match '^/(usr/(local/)?s?bin|opt|home|tmp|var)/' ) {
                $potentialPaths += $p
            }
        }

        foreach ($scriptPath in $potentialPaths) {
            if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $scriptPath) {
                $resolvedScript = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $scriptPath
                $scriptContent = Read-ArtifactContent -Path $resolvedScript
                if ($scriptContent.Count -eq 0) { continue }

                $scriptText = $scriptContent -join "`n"

                # Check script content for the same suspicious patterns
                foreach ($rsPattern in $builtinReverseShellRegex) {
                    if ($scriptText -match $rsPattern) {
                        $null = $findings.Add((New-Finding -Id 'CRON-001' -Severity 'Critical' `
                            -Category 'Persistence' `
                            -Title 'Reverse shell pattern found in cron-referenced script' `
                            -Description "Script '$scriptPath' referenced by cron job in '$($Entry.SourceFile)' contains a reverse shell pattern." `
                            -ArtifactPath $resolvedScript `
                            -Evidence @("Cron source: $($Entry.SourceFile)", "Script: $scriptPath", "Matched pattern: $rsPattern") `
                            -Recommendation 'Examine the script and the cron entry. Remove malicious content and assess compromise scope.' `
                            -MITRE 'T1053.003'))
                        break
                    }
                }

                if ($scriptText -match $base64Pattern) {
                    $null = $findings.Add((New-Finding -Id 'CRON-003' -Severity 'High' `
                        -Category 'Persistence' `
                        -Title 'Base64 encoded command in cron-referenced script' `
                        -Description "Script '$scriptPath' referenced by cron job in '$($Entry.SourceFile)' contains base64 encoded commands." `
                        -ArtifactPath $resolvedScript `
                        -Evidence @("Cron source: $($Entry.SourceFile)", "Script: $scriptPath") `
                        -Recommendation 'Decode the base64 content and analyze the underlying commands.' `
                        -MITRE 'T1053.003'))
                }

                if ($scriptText -match $downloadExecPattern) {
                    $null = $findings.Add((New-Finding -Id 'CRON-004' -Severity 'High' `
                        -Category 'Persistence' `
                        -Title 'Download-and-execute in cron-referenced script' `
                        -Description "Script '$scriptPath' referenced by cron job in '$($Entry.SourceFile)' downloads and executes remote content." `
                        -ArtifactPath $resolvedScript `
                        -Evidence @("Cron source: $($Entry.SourceFile)", "Script: $scriptPath") `
                        -Recommendation 'Identify the remote URL and analyze what is being downloaded. Remove if malicious.' `
                        -MITRE 'T1053.003'))
                }

                foreach ($susPath in $suspiciousPaths) {
                    if ($scriptText -match [regex]::Escape($susPath)) {
                        $null = $findings.Add((New-Finding -Id 'CRON-002' -Severity 'High' `
                            -Category 'Persistence' `
                            -Title 'Cron-referenced script uses suspicious path' `
                            -Description "Script '$scriptPath' referenced by cron job in '$($Entry.SourceFile)' references suspicious path '$susPath'." `
                            -ArtifactPath $resolvedScript `
                            -Evidence @("Cron source: $($Entry.SourceFile)", "Script: $scriptPath", "Suspicious path: $susPath") `
                            -Recommendation 'Investigate the script and verify its legitimacy.' `
                            -MITRE 'T1053.003'))
                        break
                    }
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # Process individual cron files (e.g., etc/crontab)
    # -------------------------------------------------------------------------
    foreach ($cronFile in $cronFiles) {
        if (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $cronFile) {
            $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $cronFile
            $content = Read-ArtifactContent -Path $resolvedPath
            $null = $analyzedFiles.Add($cronFile)

            # Determine if this is a system crontab (has user field)
            $isSystemCrontab = ($cronFile -eq 'etc/crontab' -or $cronFile -match '^etc/cron\.d/')

            foreach ($line in $content) {
                $entry = Parse-CronLine -Line $line -SourceFile $resolvedPath -IsSystemCrontab $isSystemCrontab
                if ($null -ne $entry) {
                    $null = $allCronJobs.Add($entry)
                    Analyze-CronEntry -Entry $entry
                    Check-ReferencedScript -Entry $entry
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # Process cron directories
    # -------------------------------------------------------------------------
    foreach ($cronDir in $cronDirs) {
        $dirFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $cronDir
        foreach ($file in $dirFiles) {
            $content = Read-ArtifactContent -Path $file.FullName
            $null = $analyzedFiles.Add("$cronDir/$($file.Name)")

            # System cron.d files have user field; user spool crontabs do not
            $isSystemCrontab = ($cronDir -match '^etc/cron\.')

            foreach ($line in $content) {
                $entry = Parse-CronLine -Line $line -SourceFile $file.FullName -IsSystemCrontab $isSystemCrontab
                if ($null -ne $entry) {
                    $null = $allCronJobs.Add($entry)
                    Analyze-CronEntry -Entry $entry
                    Check-ReferencedScript -Entry $entry
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # Process user crontabs in home directories (home/*/.crontab)
    # -------------------------------------------------------------------------
    $homeDir = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'home'
    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            $userCrontab = Join-Path $userDir.FullName '.crontab'
            if (Test-Path $userCrontab -PathType Leaf) {
                $content = Read-ArtifactContent -Path $userCrontab
                $null = $analyzedFiles.Add("home/$($userDir.Name)/.crontab")

                foreach ($line in $content) {
                    $entry = Parse-CronLine -Line $line -SourceFile $userCrontab -IsSystemCrontab $false
                    if ($null -ne $entry) {
                        if ([string]::IsNullOrEmpty($entry.User)) {
                            $entry.User = $userDir.Name
                        }
                        $null = $allCronJobs.Add($entry)
                        Analyze-CronEntry -Entry $entry
                        Check-ReferencedScript -Entry $entry
                    }
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # CRON-006: Informational summary
    # -------------------------------------------------------------------------
    $summaryEvidence = @(
        "Total cron files analyzed: $($analyzedFiles.Count)"
        "Total cron jobs found: $($allCronJobs.Count)"
    )

    if ($analyzedFiles.Count -gt 0) {
        $summaryEvidence += "Files analyzed:"
        foreach ($f in $analyzedFiles) {
            $summaryEvidence += "  - $f"
        }
    }

    if ($allCronJobs.Count -gt 0) {
        $summaryEvidence += "Cron jobs:"
        foreach ($job in $allCronJobs) {
            $userInfo = if ($job.User) { " (user: $($job.User))" } else { '' }
            $summaryEvidence += "  - [$($job.Schedule)]$userInfo $($job.Command)"
        }
    }

    $null = $findings.Add((New-Finding -Id 'CRON-006' -Severity 'Informational' `
        -Category 'Persistence' `
        -Title 'Cron job analysis summary' `
        -Description "Analyzed $($analyzedFiles.Count) cron file(s) and found $($allCronJobs.Count) cron job(s)." `
        -Evidence $summaryEvidence `
        -MITRE 'T1053.003'))

    Write-Verbose "Cron analysis complete: $($findings.Count) finding(s) generated from $($allCronJobs.Count) cron job(s)."

    return $findings.ToArray()
}
