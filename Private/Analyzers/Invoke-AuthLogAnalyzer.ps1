function Invoke-AuthLogAnalyzer {
    <#
    .SYNOPSIS
        Analyzes authentication log files for brute force, credential stuffing, and suspicious access patterns.
    .DESCRIPTION
        Parses syslog-formatted auth.log and secure log files to detect brute force attacks,
        successful compromises following failed attempts, privilege escalation via su/sudo,
        off-hours authentication, and credential stuffing attacks.
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

    # Auth log file locations
    $authLogFiles = @(
        'var/log/auth.log'
        'var/log/auth.log.1'
        'var/log/secure'
        'var/log/secure.1'
    )

    # Thresholds from rules with defaults
    $bruteForceThreshold = 5
    $maxUniqueUsersPerIp = 3
    $offHoursStart = 22  # 10 PM
    $offHoursEnd = 6     # 6 AM

    if ($Rules.auth_log_thresholds) {
        if ($Rules.auth_log_thresholds.brute_force_attempts) {
            $bruteForceThreshold = [int]$Rules.auth_log_thresholds.brute_force_attempts
        }
        if ($Rules.auth_log_thresholds.max_unique_users_per_ip) {
            $maxUniqueUsersPerIp = [int]$Rules.auth_log_thresholds.max_unique_users_per_ip
        }
        if ($null -ne $Rules.auth_log_thresholds.off_hours_start) {
            $offHoursStart = [int]$Rules.auth_log_thresholds.off_hours_start
        }
        if ($null -ne $Rules.auth_log_thresholds.off_hours_end) {
            $offHoursEnd = [int]$Rules.auth_log_thresholds.off_hours_end
        }
    }

    # Data structures for tracking events
    $failedAttempts = @{}       # IP -> list of {Timestamp, User, Line}
    $successfulLogins = @{}     # IP -> list of {Timestamp, User, Line, Method}
    $suToRoot = [System.Collections.ArrayList]::new()
    $sudoEntries = [System.Collections.ArrayList]::new()
    $allLogins = [System.Collections.ArrayList]::new()
    $uniqueIPs = [System.Collections.Generic.HashSet[string]]::new()
    $uniqueUsers = [System.Collections.Generic.HashSet[string]]::new()
    $totalLines = 0
    $parsedLines = 0
    $analyzedFiles = [System.Collections.ArrayList]::new()

    # -------------------------------------------------------------------------
    # Helper: Parse syslog timestamp
    # Format: "Mon DD HH:MM:SS" (e.g., "Jan  5 14:23:01")
    # -------------------------------------------------------------------------
    function Parse-SyslogTimestamp {
        param([string]$TimestampStr)

        # Syslog timestamps don't include year - assume current year
        $currentYear = (Get-Date).Year
        $formats = @(
            'MMM  d HH:mm:ss'
            'MMM dd HH:mm:ss'
            'MMM d HH:mm:ss'
        )

        $timestampWithYear = "$TimestampStr $currentYear"
        $formatsWithYear = @(
            'MMM  d HH:mm:ss yyyy'
            'MMM dd HH:mm:ss yyyy'
            'MMM d HH:mm:ss yyyy'
        )

        $parsed = [datetime]::MinValue
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        foreach ($fmt in $formatsWithYear) {
            if ([datetime]::TryParseExact($timestampWithYear, $fmt, $culture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
                return $parsed
            }
        }

        return $null
    }

    # -------------------------------------------------------------------------
    # Helper: Parse a syslog line
    # Format: "Mon DD HH:MM:SS hostname service[pid]: message"
    # -------------------------------------------------------------------------
    function Parse-SyslogLine {
        param([string]$Line)

        if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

        # Match syslog format
        if ($Line -match '^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$') {
            $timestamp = Parse-SyslogTimestamp -TimestampStr $Matches[1]
            return [PSCustomObject]@{
                Timestamp   = $timestamp
                TimestampRaw = $Matches[1]
                Hostname    = $Matches[2]
                Service     = $Matches[3]
                PID         = $Matches[4]
                Message     = $Matches[5]
                RawLine     = $Line
            }
        }

        return $null
    }

    # -------------------------------------------------------------------------
    # Helper: Check if timestamp falls in off-hours
    # -------------------------------------------------------------------------
    function Test-OffHours {
        param([datetime]$Timestamp)

        $hour = $Timestamp.Hour

        if ($offHoursStart -gt $offHoursEnd) {
            # Off-hours span midnight (e.g., 22:00 - 06:00)
            return ($hour -ge $offHoursStart -or $hour -lt $offHoursEnd)
        }
        else {
            # Off-hours within same day (e.g., 01:00 - 05:00)
            return ($hour -ge $offHoursStart -and $hour -lt $offHoursEnd)
        }
    }

    # -------------------------------------------------------------------------
    # Process each auth log file
    # -------------------------------------------------------------------------
    foreach ($logFile in $authLogFiles) {
        if (-not (Test-ArtifactExists -EvidencePath $EvidencePath -LinuxPath $logFile)) {
            Write-Verbose "Auth log not found: $logFile"
            continue
        }

        $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $logFile
        $content = Read-ArtifactContent -Path $resolvedPath
        $null = $analyzedFiles.Add($logFile)

        Write-Verbose "Processing $logFile ($($content.Count) lines)"

        foreach ($line in $content) {
            $totalLines++
            $parsed = Parse-SyslogLine -Line $line
            if ($null -eq $parsed) { continue }
            $parsedLines++

            $msg = $parsed.Message

            # ---- Failed password attempts ----
            if ($msg -match 'Failed password for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)') {
                $targetUser = $Matches[2]
                $sourceIP = $Matches[3]

                $null = $uniqueIPs.Add($sourceIP)
                $null = $uniqueUsers.Add($targetUser)

                if (-not $failedAttempts.ContainsKey($sourceIP)) {
                    $failedAttempts[$sourceIP] = [System.Collections.ArrayList]::new()
                }
                $null = $failedAttempts[$sourceIP].Add([PSCustomObject]@{
                    Timestamp    = $parsed.Timestamp
                    TimestampRaw = $parsed.TimestampRaw
                    User         = $targetUser
                    Line         = $line
                    SourceFile   = $resolvedPath
                })
            }

            # ---- Successful password authentication ----
            elseif ($msg -match 'Accepted (password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)') {
                $method = $Matches[1]
                $targetUser = $Matches[2]
                $sourceIP = $Matches[3]

                $null = $uniqueIPs.Add($sourceIP)
                $null = $uniqueUsers.Add($targetUser)

                if (-not $successfulLogins.ContainsKey($sourceIP)) {
                    $successfulLogins[$sourceIP] = [System.Collections.ArrayList]::new()
                }
                $null = $successfulLogins[$sourceIP].Add([PSCustomObject]@{
                    Timestamp    = $parsed.Timestamp
                    TimestampRaw = $parsed.TimestampRaw
                    User         = $targetUser
                    Method       = $method
                    Line         = $line
                    SourceFile   = $resolvedPath
                })

                $null = $allLogins.Add([PSCustomObject]@{
                    Timestamp    = $parsed.Timestamp
                    TimestampRaw = $parsed.TimestampRaw
                    User         = $targetUser
                    SourceIP     = $sourceIP
                    Method       = $method
                    SourceFile   = $resolvedPath
                })

                # AUTH-006: Off-hours authentication
                if ($null -ne $parsed.Timestamp -and $parsed.Timestamp -ne [datetime]::MinValue) {
                    if (Test-OffHours -Timestamp $parsed.Timestamp) {
                        $null = $findings.Add((New-Finding -Id 'AUTH-006' -Severity 'Medium' `
                            -Category 'Suspicious Access' `
                            -Title 'Authentication during off-hours' `
                            -Description "Successful login for user '$targetUser' from $sourceIP during off-hours ($($parsed.TimestampRaw))." `
                            -ArtifactPath $resolvedPath `
                            -Evidence @($line) `
                            -Recommendation "Verify this login was expected. Off-hours window: $offHoursStart`:00 - $offHoursEnd`:00." `
                            -Timestamp $parsed.Timestamp `
                            -MITRE 'T1078'))
                    }
                }
            }

            # ---- su to root ----
            elseif ($msg -match 'session opened for user root' -or
                    $msg -match 'Successful su for root by\s+(\S+)' -or
                    ($msg -match '^\(su-l\)' -and $msg -match 'session opened for user root')) {

                $fromUser = ''
                if ($msg -match 'by\s+(\S+)') { $fromUser = $Matches[1] }
                elseif ($msg -match 'for user root by\s+(\S+)') { $fromUser = $Matches[1] }
                elseif ($msg -match '\(uid=\d+\)') {
                    # Try to extract calling user from context
                    if ($line -match 'su.*?:\s+.*?\bby\s+(\S+)') { $fromUser = $Matches[1] }
                }

                $null = $suToRoot.Add([PSCustomObject]@{
                    Timestamp    = $parsed.Timestamp
                    TimestampRaw = $parsed.TimestampRaw
                    FromUser     = $fromUser
                    Line         = $line
                    SourceFile   = $resolvedPath
                })
            }

            # ---- Sudo commands ----
            elseif ($msg -match 'sudo:' -or $parsed.Service -eq 'sudo') {
                $sudoUser = ''
                $sudoCommand = ''

                if ($msg -match '(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)$') {
                    $sudoUser = $Matches[1]
                    $sudoCommand = $Matches[3]
                }
                elseif ($msg -match '^\s*(\S+)\s+:.*COMMAND=(.+)$') {
                    $sudoUser = $Matches[1]
                    $sudoCommand = $Matches[2]
                }

                if ($sudoUser -or $sudoCommand) {
                    $null = $sudoEntries.Add([PSCustomObject]@{
                        Timestamp    = $parsed.Timestamp
                        TimestampRaw = $parsed.TimestampRaw
                        User         = $sudoUser
                        Command      = $sudoCommand
                        Line         = $line
                        SourceFile   = $resolvedPath
                    })
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # AUTH-001: Successful login following brute force (same IP)
    # -------------------------------------------------------------------------
    foreach ($ip in $successfulLogins.Keys) {
        if ($failedAttempts.ContainsKey($ip)) {
            $fails = $failedAttempts[$ip]
            $successes = $successfulLogins[$ip]

            foreach ($success in $successes) {
                # Count failed attempts before this successful login
                $priorFails = @($fails | Where-Object {
                    $null -ne $_.Timestamp -and $_.Timestamp -ne [datetime]::MinValue -and
                    $null -ne $success.Timestamp -and $success.Timestamp -ne [datetime]::MinValue -and
                    $_.Timestamp -lt $success.Timestamp
                })

                if ($priorFails.Count -ge $bruteForceThreshold) {
                    $targetedUsers = ($priorFails | Select-Object -ExpandProperty User -Unique) -join ', '
                    $evidence = @(
                        "Source IP: $ip"
                        "Failed attempts before success: $($priorFails.Count)"
                        "Targeted users: $targetedUsers"
                        "Successful login as: $($success.User) via $($success.Method)"
                        "Success timestamp: $($success.TimestampRaw)"
                        "First failure: $($priorFails[0].TimestampRaw)"
                        "Last failure: $($priorFails[-1].TimestampRaw)"
                        "Successful login line: $($success.Line)"
                    )

                    $null = $findings.Add((New-Finding -Id 'AUTH-001' -Severity 'Critical' `
                        -Category 'Credential Access' `
                        -Title "Brute force success: login after $($priorFails.Count) failures from $ip" `
                        -Description "IP address $ip successfully authenticated as '$($success.User)' after $($priorFails.Count) failed login attempts. This strongly indicates a successful brute force attack." `
                        -ArtifactPath $success.SourceFile `
                        -Evidence $evidence `
                        -Recommendation 'Immediately disable the compromised account. Investigate all activity from this IP and the compromised user. Reset credentials and review for lateral movement.' `
                        -Timestamp $success.Timestamp `
                        -MITRE 'T1110'))
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # AUTH-002: Multiple failed login attempts from single IP
    # -------------------------------------------------------------------------
    foreach ($ip in $failedAttempts.Keys) {
        $fails = $failedAttempts[$ip]
        if ($fails.Count -ge $bruteForceThreshold) {
            $targetedUsers = ($fails | Select-Object -ExpandProperty User -Unique) -join ', '
            $firstAttempt = ($fails | Sort-Object Timestamp | Select-Object -First 1).TimestampRaw
            $lastAttempt = ($fails | Sort-Object Timestamp | Select-Object -Last 1).TimestampRaw

            # Sample evidence lines (first 5 and last 2)
            $sampleLines = @()
            $sortedFails = $fails | Sort-Object Timestamp
            $sampleLines += ($sortedFails | Select-Object -First 5 | ForEach-Object { $_.Line })
            if ($fails.Count -gt 7) {
                $sampleLines += "... ($($fails.Count - 7) more entries) ..."
                $sampleLines += ($sortedFails | Select-Object -Last 2 | ForEach-Object { $_.Line })
            }
            elseif ($fails.Count -gt 5) {
                $sampleLines += ($sortedFails | Select-Object -Skip 5 | ForEach-Object { $_.Line })
            }

            $evidence = @(
                "Source IP: $ip"
                "Total failed attempts: $($fails.Count)"
                "Targeted users: $targetedUsers"
                "First attempt: $firstAttempt"
                "Last attempt: $lastAttempt"
                "Threshold: $bruteForceThreshold"
            ) + $sampleLines

            $null = $findings.Add((New-Finding -Id 'AUTH-002' -Severity 'High' `
                -Category 'Credential Access' `
                -Title "Brute force: $($fails.Count) failed logins from $ip" `
                -Description "IP address $ip generated $($fails.Count) failed login attempts targeting user(s): $targetedUsers. This exceeds the brute force threshold of $bruteForceThreshold." `
                -ArtifactPath ($fails[0].SourceFile) `
                -Evidence $evidence `
                -Recommendation 'Block the source IP. Verify targeted accounts are not compromised. Review firewall and fail2ban configurations.' `
                -MITRE 'T1110'))
        }
    }

    # -------------------------------------------------------------------------
    # AUTH-003: Successful su to root
    # -------------------------------------------------------------------------
    foreach ($suEvent in $suToRoot) {
        $fromInfo = if ($suEvent.FromUser) { " by user '$($suEvent.FromUser)'" } else { '' }
        $null = $findings.Add((New-Finding -Id 'AUTH-003' -Severity 'High' `
            -Category 'Privilege Escalation' `
            -Title "Successful su to root$fromInfo" `
            -Description "A session was opened for user root via su$fromInfo at $($suEvent.TimestampRaw). This could indicate privilege escalation." `
            -ArtifactPath $suEvent.SourceFile `
            -Evidence @($suEvent.Line) `
            -Recommendation 'Verify this privilege escalation was authorized. Review what actions were performed as root.' `
            -Timestamp $suEvent.Timestamp `
            -MITRE 'T1078'))
    }

    # -------------------------------------------------------------------------
    # AUTH-004: Sudo command execution
    # -------------------------------------------------------------------------
    if ($sudoEntries.Count -gt 0) {
        $sudoByUser = $sudoEntries | Group-Object -Property User
        foreach ($group in $sudoByUser) {
            $userName = $group.Name
            $commands = $group.Group
            $evidence = @(
                "User: $userName"
                "Total sudo commands: $($commands.Count)"
                "Commands executed:"
            )
            foreach ($cmd in $commands) {
                $evidence += "  [$($cmd.TimestampRaw)] $($cmd.Command)"
            }

            $null = $findings.Add((New-Finding -Id 'AUTH-004' -Severity 'Medium' `
                -Category 'Privilege Escalation' `
                -Title "Sudo usage by '$userName': $($commands.Count) command(s)" `
                -Description "User '$userName' executed $($commands.Count) command(s) via sudo. Review for unauthorized privilege escalation." `
                -ArtifactPath ($commands[0].SourceFile) `
                -Evidence $evidence `
                -Recommendation 'Review the commands executed via sudo for any unauthorized or suspicious activity.' `
                -MITRE 'T1078'))
        }
    }

    # -------------------------------------------------------------------------
    # AUTH-005: SSH login from multiple source IPs
    # -------------------------------------------------------------------------
    $loginsByUser = $allLogins | Group-Object -Property User
    foreach ($group in $loginsByUser) {
        $userName = $group.Name
        $logins = $group.Group
        $loginIPs = $logins | Select-Object -ExpandProperty SourceIP -Unique

        if ($loginIPs.Count -gt 1) {
            $evidence = @(
                "User: $userName"
                "Unique source IPs: $($loginIPs.Count)"
                "Source IPs: $($loginIPs -join ', ')"
                "Login details:"
            )
            foreach ($login in $logins) {
                $evidence += "  [$($login.TimestampRaw)] from $($login.SourceIP) via $($login.Method)"
            }

            $null = $findings.Add((New-Finding -Id 'AUTH-005' -Severity 'Medium' `
                -Category 'Suspicious Access' `
                -Title "User '$userName' logged in from $($loginIPs.Count) different IPs" `
                -Description "User '$userName' authenticated from $($loginIPs.Count) unique source IP addresses. Multiple source IPs may indicate credential sharing, VPN usage, or compromised credentials being used from different locations." `
                -ArtifactPath ($logins[0].SourceFile) `
                -Evidence $evidence `
                -Recommendation 'Verify all source IPs are expected for this user. Investigate any unfamiliar IPs for potential unauthorized access.' `
                -MITRE 'T1078'))
        }
    }

    # -------------------------------------------------------------------------
    # AUTH-007: Credential stuffing - multiple usernames from same IP
    # -------------------------------------------------------------------------
    foreach ($ip in $failedAttempts.Keys) {
        $fails = $failedAttempts[$ip]
        $targetedUsers = $fails | Select-Object -ExpandProperty User -Unique

        if ($targetedUsers.Count -ge $maxUniqueUsersPerIp) {
            $evidence = @(
                "Source IP: $ip"
                "Unique usernames targeted: $($targetedUsers.Count)"
                "Usernames: $($targetedUsers -join ', ')"
                "Total failed attempts: $($fails.Count)"
                "Threshold: $maxUniqueUsersPerIp unique users per IP"
            )

            # Add sample lines
            $sortedFails = $fails | Sort-Object Timestamp
            $sampleLines = ($sortedFails | Select-Object -First 5 | ForEach-Object { $_.Line })
            $evidence += $sampleLines

            $null = $findings.Add((New-Finding -Id 'AUTH-007' -Severity 'High' `
                -Category 'Credential Access' `
                -Title "Credential stuffing: $($targetedUsers.Count) usernames targeted from $ip" `
                -Description "IP address $ip attempted authentication against $($targetedUsers.Count) unique usernames, exceeding the threshold of $maxUniqueUsersPerIp. This pattern is consistent with credential stuffing or user enumeration attacks." `
                -ArtifactPath ($fails[0].SourceFile) `
                -Evidence $evidence `
                -Recommendation 'Block the source IP immediately. Check if any of the targeted accounts were compromised. Implement rate limiting and account lockout policies.' `
                -MITRE 'T1110'))
        }
    }

    # -------------------------------------------------------------------------
    # AUTH-008: Authentication summary
    # -------------------------------------------------------------------------
    $totalFailedAll = 0
    foreach ($ip in $failedAttempts.Keys) {
        $totalFailedAll += $failedAttempts[$ip].Count
    }

    $summaryEvidence = @(
        "Files analyzed: $($analyzedFiles -join ', ')"
        "Total log lines processed: $totalLines"
        "Successfully parsed lines: $parsedLines"
        "Total successful logins: $($allLogins.Count)"
        "Total failed login attempts: $totalFailedAll"
        "Unique source IPs: $($uniqueIPs.Count)"
        "Unique usernames: $($uniqueUsers.Count)"
        "Su-to-root events: $($suToRoot.Count)"
        "Sudo command entries: $($sudoEntries.Count)"
    )

    if ($uniqueIPs.Count -gt 0) {
        $summaryEvidence += "Source IPs observed: $($uniqueIPs -join ', ')"
    }
    if ($uniqueUsers.Count -gt 0) {
        $summaryEvidence += "Users observed: $($uniqueUsers -join ', ')"
    }

    $null = $findings.Add((New-Finding -Id 'AUTH-008' -Severity 'Informational' `
        -Category 'Authentication' `
        -Title 'Authentication log analysis summary' `
        -Description "Analyzed $($analyzedFiles.Count) authentication log file(s) containing $totalLines total lines. Found $($allLogins.Count) successful login(s) and $totalFailedAll failed attempt(s) from $($uniqueIPs.Count) unique IP(s)." `
        -Evidence $summaryEvidence `
        -MITRE 'T1110'))

    Write-Verbose "Auth log analysis complete: $($findings.Count) finding(s) generated."

    return $findings.ToArray()
}
