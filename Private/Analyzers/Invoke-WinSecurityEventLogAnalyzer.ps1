function Invoke-WinSecurityEventLogAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows Security event log for security-relevant events.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $secEventsPath = Join-Path $EvidencePath 'eventlogs/security_events.csv'
    if (-not (Test-Path $secEventsPath)) {
        Write-Verbose "Security event log not found: $secEventsPath"
        return $findings.ToArray()
    }

    # Import security events
    $events = @()
    try {
        $events = Import-Csv -Path $secEventsPath -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to parse security_events.csv: $_"
        return $findings.ToArray()
    }

    if ($events.Count -eq 0) {
        return $findings.ToArray()
    }

    # Normalize event ID field name
    $idField = 'Id'
    if ($events[0].PSObject.Properties['EventId']) { $idField = 'EventId' }
    elseif ($events[0].PSObject.Properties['EventID']) { $idField = 'EventID' }
    elseif ($events[0].PSObject.Properties['Event_ID']) { $idField = 'Event_ID' }

    # Normalize time field
    $timeField = 'TimeCreated'
    if ($events[0].PSObject.Properties['Time']) { $timeField = 'Time' }
    elseif ($events[0].PSObject.Properties['TimeGenerated']) { $timeField = 'TimeGenerated' }
    elseif ($events[0].PSObject.Properties['Timestamp']) { $timeField = 'Timestamp' }

    # Normalize message field
    $msgField = 'Message'
    if ($events[0].PSObject.Properties['message']) { $msgField = 'message' }

    # Configurable thresholds
    $failedLogonThreshold = 5
    if ($Rules.ContainsKey('failed_logon_threshold')) { $failedLogonThreshold = [int]$Rules['failed_logon_threshold'] }

    $businessHoursStart = 6
    $businessHoursEnd = 22
    if ($Rules.ContainsKey('business_hours_start')) { $businessHoursStart = [int]$Rules['business_hours_start'] }
    if ($Rules.ContainsKey('business_hours_end')) { $businessHoursEnd = [int]$Rules['business_hours_end'] }

    # Categorize events by ID
    $eventsByID = @{}
    $parsedEvents = @()

    foreach ($evt in $events) {
        $eventId = 0
        [int]::TryParse($evt.$idField, [ref]$eventId) | Out-Null

        $timeCreated = $null
        if ($evt.PSObject.Properties[$timeField] -and -not [string]::IsNullOrWhiteSpace($evt.$timeField)) {
            try { $timeCreated = [datetime]::Parse($evt.$timeField) } catch { }
        }

        $message = ''
        if ($evt.PSObject.Properties[$msgField]) { $message = $evt.$msgField }

        # Extract source IP/workstation from message for logon events
        $sourceIP = ''
        $sourceWorkstation = ''
        $targetAccount = ''

        if ($message -match 'Source Network Address:\s*(\S+)') { $sourceIP = $Matches[1] }
        if ($message -match 'Workstation Name:\s*(\S+)') { $sourceWorkstation = $Matches[1] }
        if ($message -match 'Account Name:\s*(\S+)') { $targetAccount = $Matches[1] }

        $parsed = [PSCustomObject]@{
            EventId          = $eventId
            TimeCreated      = $timeCreated
            Message          = $message
            SourceIP         = $sourceIP
            SourceWorkstation = $sourceWorkstation
            TargetAccount    = $targetAccount
            RawEvent         = $evt
        }
        $parsedEvents += $parsed

        if (-not $eventsByID.ContainsKey($eventId)) {
            $eventsByID[$eventId] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $eventsByID[$eventId].Add($parsed)
    }

    # ----------------------------------------------------------------
    # WEVT-001: Brute force success (failed logons then success from same source)
    # ----------------------------------------------------------------
    $failedLogons = @()
    if ($eventsByID.ContainsKey(4625)) { $failedLogons = $eventsByID[4625] }
    $successLogons = @()
    if ($eventsByID.ContainsKey(4624)) { $successLogons = $eventsByID[4624] }

    # Group failed logons by source IP
    $failedBySource = @{}
    foreach ($fl in $failedLogons) {
        $source = if (-not [string]::IsNullOrWhiteSpace($fl.SourceIP) -and $fl.SourceIP -ne '-') { $fl.SourceIP } else { $fl.SourceWorkstation }
        if ([string]::IsNullOrWhiteSpace($source) -or $source -eq '-') { continue }
        if (-not $failedBySource.ContainsKey($source)) { $failedBySource[$source] = @() }
        $failedBySource[$source] += $fl
    }

    $bruteForceSuccesses = @()
    foreach ($source in $failedBySource.Keys) {
        $failures = $failedBySource[$source]
        if ($failures.Count -lt $failedLogonThreshold) { continue }

        # Check if there was a successful logon from same source after failures
        $lastFailure = $failures | Where-Object { $null -ne $_.TimeCreated } | Sort-Object TimeCreated | Select-Object -Last 1
        if ($null -eq $lastFailure -or $null -eq $lastFailure.TimeCreated) { continue }

        $successFromSameSource = $successLogons | Where-Object {
            $null -ne $_.TimeCreated -and
            $_.TimeCreated -gt $lastFailure.TimeCreated -and
            ($_.SourceIP -eq $source -or $_.SourceWorkstation -eq $source)
        }

        if ($successFromSameSource.Count -gt 0) {
            $firstSuccess = $successFromSameSource | Sort-Object TimeCreated | Select-Object -First 1
            $bruteForceSuccesses += "Source=$source: $($failures.Count) failures followed by successful logon at $($firstSuccess.TimeCreated)"
        }
    }

    if ($bruteForceSuccesses.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WEVT-001' -Severity 'Critical' -Category 'Event Log' `
            -Title 'Successful logon after brute force attempts detected' `
            -Description "Found $($bruteForceSuccesses.Count) instance(s) where successful logon occurred after multiple failed attempts from the same source, indicating a likely brute force compromise." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($bruteForceSuccesses | Select-Object -First 10) `
            -Recommendation 'Immediately investigate compromised accounts. Reset passwords, review account activity, and block the source IPs. Enable account lockout policies.' `
            -MITRE 'T1110.001' `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Successful brute force attack grants unauthorized access to the system, enabling data theft, lateral movement, and further compromise.'))
    }

    # ----------------------------------------------------------------
    # WEVT-002: Multiple failed logon attempts from single source
    # ----------------------------------------------------------------
    $bruteForceAttempts = @()
    foreach ($source in $failedBySource.Keys) {
        if ($failedBySource[$source].Count -ge $failedLogonThreshold) {
            $bruteForceAttempts += "Source=$source: $($failedBySource[$source].Count) failed logon attempts"
        }
    }

    if ($bruteForceAttempts.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WEVT-002' -Severity 'High' -Category 'Event Log' `
            -Title "Multiple failed logon attempts detected (threshold: $failedLogonThreshold)" `
            -Description "Found $($bruteForceAttempts.Count) source(s) exceeding the failed logon threshold of $failedLogonThreshold attempts. This indicates brute force or password spraying activity." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($bruteForceAttempts | Select-Object -First 15) `
            -Recommendation 'Block offending source IPs, review account lockout policies, and consider implementing multi-factor authentication.' `
            -MITRE 'T1110' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Brute force attempts may eventually succeed in compromising accounts, especially those with weak or default passwords.'))
    }

    # ----------------------------------------------------------------
    # WEVT-003: Account created (4720)
    # ----------------------------------------------------------------
    if ($eventsByID.ContainsKey(4720)) {
        $newAccounts = $eventsByID[4720]
        $accountEvidence = @()
        foreach ($evt in $newAccounts) {
            $acctName = ''
            if ($evt.Message -match 'Account Name:\s*(\S+)') { $acctName = $Matches[1] }
            $timeStr = if ($null -ne $evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' }
            $accountEvidence += "Account created: $acctName at $timeStr"
        }

        $findings.Add((New-Finding -Id 'WEVT-003' -Severity 'High' -Category 'Event Log' `
            -Title "New user account(s) created ($($newAccounts.Count))" `
            -Description "Found $($newAccounts.Count) account creation event(s) (Event ID 4720). Unauthorized account creation may indicate persistence or privilege escalation by an attacker." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($accountEvidence | Select-Object -First 10) `
            -Recommendation 'Verify all created accounts are authorized. Disable or remove unauthorized accounts immediately.' `
            -MITRE 'T1136.001' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Unauthorized account creation provides persistent access and may be used for lateral movement or privilege escalation.'))
    }

    # ----------------------------------------------------------------
    # WEVT-004: Account added to privileged group (4728/4732/4756)
    # ----------------------------------------------------------------
    $privGroupEvents = @()
    foreach ($eid in @(4728, 4732, 4756)) {
        if ($eventsByID.ContainsKey($eid)) {
            $privGroupEvents += $eventsByID[$eid]
        }
    }

    if ($privGroupEvents.Count -gt 0) {
        $privGroupEvidence = @()
        foreach ($evt in $privGroupEvents) {
            $groupName = ''
            $memberName = ''
            if ($evt.Message -match 'Group Name:\s*(.+?)(\r|\n|$)') { $groupName = $Matches[1].Trim() }
            if ($evt.Message -match 'Member.*Account Name:\s*(\S+)') { $memberName = $Matches[1] }
            $timeStr = if ($null -ne $evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' }
            $privGroupEvidence += "Event $($evt.EventId): $memberName added to '$groupName' at $timeStr"
        }

        $findings.Add((New-Finding -Id 'WEVT-004' -Severity 'High' -Category 'Event Log' `
            -Title "Account(s) added to privileged group ($($privGroupEvents.Count) events)" `
            -Description "Found $($privGroupEvents.Count) event(s) where accounts were added to security groups (Event IDs 4728/4732/4756). This may indicate privilege escalation." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($privGroupEvidence | Select-Object -First 10) `
            -Recommendation 'Verify all group membership changes are authorized. Review the added accounts and remove unauthorized members from privileged groups.' `
            -MITRE 'T1098' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Adding accounts to privileged groups grants elevated permissions, enabling access to sensitive resources and administrative capabilities.'))
    }

    # ----------------------------------------------------------------
    # WEVT-005: Audit log cleared (1102 or 104)
    # ----------------------------------------------------------------
    $logClearEvents = @()
    foreach ($eid in @(1102, 104)) {
        if ($eventsByID.ContainsKey($eid)) {
            $logClearEvents += $eventsByID[$eid]
        }
    }

    if ($logClearEvents.Count -gt 0) {
        $clearEvidence = @()
        foreach ($evt in $logClearEvents) {
            $timeStr = if ($null -ne $evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' }
            $clearEvidence += "Event $($evt.EventId): Audit log cleared at $timeStr"
            if (-not [string]::IsNullOrWhiteSpace($evt.TargetAccount)) {
                $clearEvidence += "  By account: $($evt.TargetAccount)"
            }
        }

        $findings.Add((New-Finding -Id 'WEVT-005' -Severity 'Critical' -Category 'Event Log' `
            -Title "Audit log cleared ($($logClearEvents.Count) events)" `
            -Description "Found $($logClearEvents.Count) event(s) indicating the security audit log was cleared (Event IDs 1102/104). This is a strong indicator of anti-forensic activity." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($clearEvidence | Select-Object -First 10) `
            -Recommendation 'Investigate who cleared the logs and when. Correlate with other evidence to reconstruct the timeline of events. Forward logs to a SIEM to prevent loss.' `
            -MITRE 'T1070.001' `
            -CVSSv3Score '9.1' `
            -TechnicalImpact 'Clearing audit logs destroys forensic evidence and hides attacker activity, making incident response significantly more difficult.'))
    }

    # ----------------------------------------------------------------
    # WEVT-006: Logon outside business hours (4624 between 22:00-06:00)
    # ----------------------------------------------------------------
    $offHoursLogons = @()
    foreach ($evt in $successLogons) {
        if ($null -eq $evt.TimeCreated) { continue }
        $hour = $evt.TimeCreated.Hour
        if ($hour -ge $businessHoursEnd -or $hour -lt $businessHoursStart) {
            $offHoursLogons += "Logon at $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) from $($evt.SourceIP) account=$($evt.TargetAccount)"
        }
    }

    if ($offHoursLogons.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WEVT-006' -Severity 'Medium' -Category 'Event Log' `
            -Title "Logon events outside business hours ($($offHoursLogons.Count) events)" `
            -Description "Found $($offHoursLogons.Count) successful logon event(s) outside business hours ($($businessHoursEnd):00-$($businessHoursStart):00). Off-hours logons may indicate unauthorized access." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($offHoursLogons | Select-Object -First 15) `
            -Recommendation 'Verify off-hours logons are from authorized personnel. Investigate any unexpected accounts or source addresses.' `
            -MITRE 'T1078' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Off-hours logons may indicate compromised credentials being used when legitimate users are unlikely to notice.'))
    }

    # ----------------------------------------------------------------
    # WEVT-007: Service installed (7045) with suspicious binary path
    # ----------------------------------------------------------------
    if ($eventsByID.ContainsKey(7045)) {
        $serviceEvents = $eventsByID[7045]
        $suspiciousServices = @()
        $allServiceEvidence = @()

        $suspiciousServicePatterns = @(
            '\\temp\\', '\\tmp\\', '\\appdata\\', 'powershell', 'cmd\.exe', 'rundll32',
            '\\users\\public\\', '\\programdata\\', 'mshta', 'wscript', 'cscript',
            'certutil', 'bitsadmin', '\.bat$', '\.vbs$', '\.ps1$'
        )

        foreach ($evt in $serviceEvents) {
            $serviceName = ''
            $servicePath = ''
            if ($evt.Message -match 'Service Name:\s*(.+?)(\r|\n|$)') { $serviceName = $Matches[1].Trim() }
            if ($evt.Message -match 'Service File Name:\s*(.+?)(\r|\n|$)') { $servicePath = $Matches[1].Trim() }
            $timeStr = if ($null -ne $evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' }

            $isSuspicious = $false
            foreach ($pattern in $suspiciousServicePatterns) {
                if ($servicePath -match $pattern) {
                    $isSuspicious = $true
                    break
                }
            }

            $entry = "Service '$serviceName' installed at $timeStr : $servicePath"
            $allServiceEvidence += $entry
            if ($isSuspicious) {
                $suspiciousServices += $entry
            }
        }

        if ($suspiciousServices.Count -gt 0) {
            $findings.Add((New-Finding -Id 'WEVT-007' -Severity 'High' -Category 'Event Log' `
                -Title "Suspicious service installed ($($suspiciousServices.Count) events)" `
                -Description "Found $($suspiciousServices.Count) service installation event(s) (Event ID 7045) with suspicious binary paths. Malware and attackers commonly install services for persistence and privilege escalation." `
                -ArtifactPath 'eventlogs/security_events.csv' `
                -Evidence @($suspiciousServices | Select-Object -First 10) `
                -Recommendation 'Investigate each suspicious service immediately. Check the binary for malware signatures and verify the service is authorized.' `
                -MITRE 'T1543.003' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact 'Malicious service installation provides SYSTEM-level persistent access and survives reboots.'))
        }
        elseif ($allServiceEvidence.Count -gt 0) {
            # Still flag all service installations at lower severity
            $findings.Add((New-Finding -Id 'WEVT-007' -Severity 'Medium' -Category 'Event Log' `
                -Title "New service(s) installed ($($allServiceEvidence.Count) events)" `
                -Description "Found $($allServiceEvidence.Count) service installation event(s) (Event ID 7045). While no obviously suspicious paths were detected, service installations should be reviewed." `
                -ArtifactPath 'eventlogs/security_events.csv' `
                -Evidence @($allServiceEvidence | Select-Object -First 10) `
                -Recommendation 'Review installed services to verify they are authorized and legitimate.' `
                -MITRE 'T1543.003' `
                -CVSSv3Score '5.3' `
                -TechnicalImpact 'Service installation may indicate persistence mechanism or legitimate software deployment.'))
        }
    }

    # ----------------------------------------------------------------
    # WEVT-008: Special privilege logon (4672) for non-admin accounts
    # ----------------------------------------------------------------
    if ($eventsByID.ContainsKey(4672)) {
        $privLogons = $eventsByID[4672]
        $knownAdminAccounts = @('Administrator', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')
        if ($Rules.ContainsKey('admin_accounts') -and $Rules['admin_accounts'] -is [array]) {
            $knownAdminAccounts += $Rules['admin_accounts']
        }

        $unexpectedPrivLogons = @()
        foreach ($evt in $privLogons) {
            $account = $evt.TargetAccount
            if ([string]::IsNullOrWhiteSpace($account) -or $account -eq '-') { continue }
            # Skip known admin/system accounts
            $isKnown = $false
            foreach ($admin in $knownAdminAccounts) {
                if ($account -eq $admin -or $account -match '\$$') {
                    $isKnown = $true
                    break
                }
            }
            if (-not $isKnown) {
                $timeStr = if ($null -ne $evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' }
                $unexpectedPrivLogons += "Account=$account at $timeStr"
            }
        }

        $unexpectedPrivLogons = @($unexpectedPrivLogons | Select-Object -Unique)
        if ($unexpectedPrivLogons.Count -gt 0) {
            $findings.Add((New-Finding -Id 'WEVT-008' -Severity 'Medium' -Category 'Event Log' `
                -Title "Special privilege logon for non-admin accounts ($($unexpectedPrivLogons.Count) events)" `
                -Description "Found $($unexpectedPrivLogons.Count) special privilege logon event(s) (Event ID 4672) for accounts not in the expected administrator list. This may indicate privilege escalation." `
                -ArtifactPath 'eventlogs/security_events.csv' `
                -Evidence @($unexpectedPrivLogons | Select-Object -First 15) `
                -Recommendation 'Review which accounts have elevated privileges. Ensure principle of least privilege is enforced.' `
                -MITRE 'T1078.002' `
                -CVSSv3Score '6.5' `
                -TechnicalImpact 'Non-admin accounts with special privileges may indicate privilege escalation or misconfigured access controls.'))
        }
    }

    # ----------------------------------------------------------------
    # WEVT-009: Account lockout events (4740)
    # ----------------------------------------------------------------
    if ($eventsByID.ContainsKey(4740)) {
        $lockoutEvents = $eventsByID[4740]
        $lockoutEvidence = @()
        foreach ($evt in $lockoutEvents) {
            $timeStr = if ($null -ne $evt.TimeCreated) { $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' }
            $lockoutEvidence += "Account=$($evt.TargetAccount) locked out at $timeStr from $($evt.SourceWorkstation)"
        }

        $findings.Add((New-Finding -Id 'WEVT-009' -Severity 'High' -Category 'Event Log' `
            -Title "Account lockout events detected ($($lockoutEvents.Count) events)" `
            -Description "Found $($lockoutEvents.Count) account lockout event(s) (Event ID 4740). Account lockouts typically indicate brute force password attacks." `
            -ArtifactPath 'eventlogs/security_events.csv' `
            -Evidence @($lockoutEvidence | Select-Object -First 15) `
            -Recommendation 'Investigate the source of the lockouts. Block offending IPs and review affected accounts for compromise.' `
            -MITRE 'T1110' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Account lockouts indicate active brute force attacks. While lockout prevents immediate access, the attacker may succeed against other accounts.'))
    }

    # ----------------------------------------------------------------
    # WEVT-010: Event log summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()
    $summaryItems += "Total security events: $($parsedEvents.Count)"

    # Timespan
    $eventsWithTime = $parsedEvents | Where-Object { $null -ne $_.TimeCreated }
    if ($eventsWithTime.Count -gt 0) {
        $earliest = ($eventsWithTime | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        $latest = ($eventsWithTime | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
        $summaryItems += "Time range: $($earliest.ToString('yyyy-MM-dd HH:mm:ss')) to $($latest.ToString('yyyy-MM-dd HH:mm:ss'))"
        $span = $latest - $earliest
        $summaryItems += "Duration: $($span.Days) days, $($span.Hours) hours"
    }

    # Top event IDs
    $topEvents = $eventsByID.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 10
    foreach ($entry in $topEvents) {
        $eventDesc = switch ($entry.Key) {
            4624  { 'Successful logon' }
            4625  { 'Failed logon' }
            4634  { 'Logoff' }
            4648  { 'Explicit credential logon' }
            4672  { 'Special privileges assigned' }
            4720  { 'Account created' }
            4722  { 'Account enabled' }
            4724  { 'Password reset' }
            4728  { 'Member added to global group' }
            4732  { 'Member added to local group' }
            4740  { 'Account lockout' }
            4756  { 'Member added to universal group' }
            7045  { 'Service installed' }
            1102  { 'Audit log cleared' }
            104   { 'Event log cleared' }
            default { '' }
        }
        $desc = if ($eventDesc) { " ($eventDesc)" } else { '' }
        $summaryItems += "Event ID $($entry.Key)$desc : $($entry.Value.Count) events"
    }

    $findings.Add((New-Finding -Id 'WEVT-010' -Severity 'Informational' -Category 'Event Log' `
        -Title 'Security event log summary' `
        -Description 'Summary of Windows Security event log analysis including total events, timespan, and top event IDs.' `
        -ArtifactPath 'eventlogs/security_events.csv' `
        -Evidence $summaryItems `
        -Recommendation 'Review the event log summary for anomalies and correlate with other findings.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of security event log contents.'))

    return $findings.ToArray()
}
