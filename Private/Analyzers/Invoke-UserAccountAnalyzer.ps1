function Invoke-UserAccountAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Linux user account configuration for security issues.
    .DESCRIPTION
        Examines /etc/passwd, /etc/shadow, and /etc/group for misconfigurations
        including non-root UID 0 accounts, empty passwords, service accounts with
        interactive shells, missing password expiration, weak hash algorithms, and
        duplicate UIDs.
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
    $analyzerCategory = 'User Accounts'
    $mitreValidAccounts = 'T1078'
    $mitreShadowFile = 'T1003.008'

    # ----------------------------------------------------------------
    # Load artifacts
    # ----------------------------------------------------------------
    $passwdPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/passwd'
    $shadowPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/shadow'
    $groupPath  = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/group'

    $passwdLines = Read-ArtifactContent -Path $passwdPath
    $shadowLines = Read-ArtifactContent -Path $shadowPath
    $groupLines  = Read-ArtifactContent -Path $groupPath

    if ($passwdLines.Count -eq 0) {
        Write-Verbose "UserAccountAnalyzer: /etc/passwd not found or empty, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Parse /etc/passwd into structured objects
    # Format: username:password:uid:gid:gecos:home:shell
    # ----------------------------------------------------------------
    $passwdEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($line in $passwdLines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }

        $fields = $line.Split(':')
        if ($fields.Count -lt 7) { continue }

        $entry = @{
            Username = $fields[0]
            Password = $fields[1]
            UID      = 0
            GID      = 0
            GECOS    = $fields[4]
            Home     = $fields[5]
            Shell    = $fields[6]
            RawLine  = $line
        }

        # Parse UID/GID safely
        $uidVal = 0
        if ([int]::TryParse($fields[2], [ref]$uidVal)) {
            $entry.UID = $uidVal
        }
        $gidVal = 0
        if ([int]::TryParse($fields[3], [ref]$gidVal)) {
            $entry.GID = $gidVal
        }

        $passwdEntries.Add($entry)
    }

    # ----------------------------------------------------------------
    # Parse /etc/shadow into a lookup hashtable
    # Format: username:hash:lastchanged:min:max:warn:inactive:expire:reserved
    # ----------------------------------------------------------------
    $shadowMap = @{}
    foreach ($line in $shadowLines) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }

        $fields = $line.Split(':')
        if ($fields.Count -lt 2) { continue }

        $shadowEntry = @{
            Username    = $fields[0]
            Hash        = if ($fields.Count -ge 2) { $fields[1] } else { '' }
            LastChanged = if ($fields.Count -ge 3) { $fields[2] } else { '' }
            MinDays     = if ($fields.Count -ge 4) { $fields[3] } else { '' }
            MaxDays     = if ($fields.Count -ge 5) { $fields[4] } else { '' }
            WarnDays    = if ($fields.Count -ge 6) { $fields[5] } else { '' }
            Inactive    = if ($fields.Count -ge 7) { $fields[6] } else { '' }
            Expire      = if ($fields.Count -ge 8) { $fields[7] } else { '' }
            Reserved    = if ($fields.Count -ge 9) { $fields[8] } else { '' }
            RawLine     = $line
        }

        $shadowMap[$fields[0]] = $shadowEntry
    }

    # ----------------------------------------------------------------
    # ACCT-001 (Critical): Non-root accounts with UID 0
    # ----------------------------------------------------------------
    $uid0Accounts = $passwdEntries | Where-Object { $_.UID -eq 0 -and $_.Username -ne 'root' }
    foreach ($acct in $uid0Accounts) {
        $findings.Add((New-Finding `
            -Id 'ACCT-001' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title "Non-root account with UID 0: $($acct.Username)" `
            -Description "Account '$($acct.Username)' has UID 0, granting full root-equivalent privileges. Only the 'root' account should have UID 0." `
            -ArtifactPath $passwdPath `
            -Evidence @($acct.RawLine) `
            -Recommendation 'Remove the UID 0 assignment from this account or disable it. Investigate whether this account was created legitimately or is an indicator of compromise.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '9.8' `
            -TechnicalImpact 'Provides full root-equivalent privileges to a non-root account, enabling complete system compromise and potentially indicating a backdoor account.'
        ))
    }

    # ----------------------------------------------------------------
    # ACCT-002 (High): Accounts with empty password field in shadow
    # ----------------------------------------------------------------
    foreach ($username in $shadowMap.Keys) {
        $hash = $shadowMap[$username].Hash
        # Empty password: the hash field is literally empty string or just ""
        if ($hash -eq '' -or $hash -eq '""') {
            $findings.Add((New-Finding `
                -Id 'ACCT-002' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title "Account with empty password: $username" `
                -Description "Account '$username' has an empty password field in /etc/shadow, allowing login without a password." `
                -ArtifactPath $shadowPath `
                -Evidence @("$($username)::<remaining fields redacted>") `
                -Recommendation 'Set a strong password for this account or lock it using: passwd -l <username>' `
                -MITRE $mitreShadowFile `
                -CVSSv3Score '8.6' `
                -TechnicalImpact 'Allows unauthenticated login to the system without any password, enabling unauthorized access and potential privilege escalation.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # ACCT-003 (Medium): Service accounts with interactive shells
    # Allowed exceptions: root, sync, shutdown, halt
    # ----------------------------------------------------------------
    $interactiveShells = @('/bin/bash', '/bin/sh', '/bin/zsh')
    $shellExceptions = @('root', 'sync', 'shutdown', 'halt')

    $serviceAccountsWithShell = $passwdEntries | Where-Object {
        $_.UID -lt 1000 -and
        $_.Username -notin $shellExceptions -and
        $_.Shell -in $interactiveShells
    }

    foreach ($acct in $serviceAccountsWithShell) {
        $findings.Add((New-Finding `
            -Id 'ACCT-003' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Service account with interactive shell: $($acct.Username)" `
            -Description "Service account '$($acct.Username)' (UID $($acct.UID)) has interactive shell '$($acct.Shell)'. Service accounts should use /usr/sbin/nologin or /bin/false." `
            -ArtifactPath $passwdPath `
            -Evidence @($acct.RawLine) `
            -Recommendation "Change the shell to /usr/sbin/nologin or /bin/false: usermod -s /usr/sbin/nologin $($acct.Username)" `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Service account with interactive shell could be leveraged for unauthorized access if compromised, providing a foothold for lateral movement.'
        ))
    }

    # ----------------------------------------------------------------
    # ACCT-004 (Low): Accounts with no password expiration set
    # Check MaxDays field - empty or 99999 means no expiration
    # Only check accounts that have a valid password hash (not locked/disabled)
    # ----------------------------------------------------------------
    foreach ($entry in $passwdEntries) {
        $username = $entry.Username
        if (-not $shadowMap.ContainsKey($username)) { continue }

        $shadow = $shadowMap[$username]
        $hash = $shadow.Hash

        # Skip locked/disabled accounts (hash starts with ! or * or is empty)
        if ([string]::IsNullOrWhiteSpace($hash) -or $hash.StartsWith('!') -or $hash.StartsWith('*')) {
            continue
        }

        $maxDays = $shadow.MaxDays
        $maxDaysInt = 0
        $hasExpiration = $false

        if (-not [string]::IsNullOrWhiteSpace($maxDays) -and [int]::TryParse($maxDays, [ref]$maxDaysInt)) {
            # 99999 is the default "no expiration" value
            if ($maxDaysInt -gt 0 -and $maxDaysInt -lt 99999) {
                $hasExpiration = $true
            }
        }

        if (-not $hasExpiration) {
            $findings.Add((New-Finding `
                -Id 'ACCT-004' `
                -Severity 'Low' `
                -Category $analyzerCategory `
                -Title "No password expiration: $username" `
                -Description "Account '$username' has no password expiration set (MaxDays: $maxDays). Passwords should be rotated periodically." `
                -ArtifactPath $shadowPath `
                -Evidence @("$username - MaxDays: $maxDays") `
                -Recommendation "Set password expiration: chage -M 90 $username" `
                -MITRE $mitreValidAccounts `
                -CVSSv3Score '2.6' `
                -TechnicalImpact 'Non-expiring passwords increase the window of opportunity for credential-based attacks if the password is compromised.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # ACCT-005 (Informational): Summary of user accounts
    # ----------------------------------------------------------------
    $totalAccounts = $passwdEntries.Count
    $accountsWithShell = @($passwdEntries | Where-Object { $_.Shell -in $interactiveShells }).Count
    $uid0Count = @($passwdEntries | Where-Object { $_.UID -eq 0 }).Count
    $regularUsers = @($passwdEntries | Where-Object { $_.UID -ge 1000 }).Count
    $serviceAccounts = @($passwdEntries | Where-Object { $_.UID -gt 0 -and $_.UID -lt 1000 }).Count

    $summaryEvidence = @(
        "Total accounts: $totalAccounts"
        "Accounts with interactive shell: $accountsWithShell"
        "UID 0 accounts: $uid0Count"
        "Regular users (UID >= 1000): $regularUsers"
        "Service accounts (0 < UID < 1000): $serviceAccounts"
    )

    $findings.Add((New-Finding `
        -Id 'ACCT-005' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'User account summary' `
        -Description 'Summary of all user accounts found in /etc/passwd.' `
        -ArtifactPath $passwdPath `
        -Evidence $summaryEvidence `
        -MITRE $mitreValidAccounts `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    # ----------------------------------------------------------------
    # ACCT-006 (High): Accounts using weak hash algorithms
    # $1$ = MD5, DES = no $ prefix (and not * or ! which are locked)
    # ----------------------------------------------------------------
    foreach ($username in $shadowMap.Keys) {
        $hash = $shadowMap[$username].Hash

        # Skip locked/disabled/empty accounts
        if ([string]::IsNullOrWhiteSpace($hash) -or $hash -eq '*' -or $hash -eq '!!' -or $hash -eq '!' -or $hash.StartsWith('!') -or $hash.StartsWith('*')) {
            continue
        }

        $weakAlgorithm = $null

        if ($hash.StartsWith('$1$')) {
            $weakAlgorithm = 'MD5 ($1$)'
        }
        elseif (-not $hash.StartsWith('$')) {
            # DES hash - no $ prefix, not a locked/disabled marker
            # DES hashes are typically 13 characters
            $weakAlgorithm = 'DES (legacy)'
        }

        if ($weakAlgorithm) {
            # Redact the actual hash in evidence for security
            $hashPrefix = if ($hash.Length -gt 6) { $hash.Substring(0, 6) + '...' } else { $hash }
            $findings.Add((New-Finding `
                -Id 'ACCT-006' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title "Weak password hash algorithm for: $username" `
                -Description "Account '$username' uses the weak $weakAlgorithm hashing algorithm. Modern systems should use SHA-512 ($6$) or yescrypt ($y$)." `
                -ArtifactPath $shadowPath `
                -Evidence @("$username uses $weakAlgorithm (hash prefix: $hashPrefix)") `
                -Recommendation "Force a password change to rehash with a stronger algorithm: passwd $username. Update /etc/login.defs ENCRYPT_METHOD to SHA512 or YESCRYPT." `
                -MITRE $mitreShadowFile `
                -CVSSv3Score '7.5' `
                -TechnicalImpact 'Weak password hashing algorithm enables rapid offline brute-force cracking of password hashes, potentially exposing account credentials.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # ACCT-007 (Medium): Duplicate UIDs
    # ----------------------------------------------------------------
    $uidGroups = $passwdEntries | Group-Object -Property UID | Where-Object { $_.Count -gt 1 }
    foreach ($group in $uidGroups) {
        $uid = $group.Name
        $usernames = ($group.Group | ForEach-Object { $_.Username }) -join ', '
        $evidenceLines = $group.Group | ForEach-Object { $_.RawLine }

        $findings.Add((New-Finding `
            -Id 'ACCT-007' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Duplicate UID detected: $uid" `
            -Description "Multiple accounts share UID $uid ($usernames). Duplicate UIDs can lead to privilege confusion and complicate auditing." `
            -ArtifactPath $passwdPath `
            -Evidence @($evidenceLines) `
            -Recommendation 'Assign unique UIDs to each account. Investigate whether duplicate UIDs were intentionally configured or indicate compromise.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Duplicate UIDs allow multiple accounts to share the same privileges, complicating auditing and potentially masking unauthorized access.'
        ))
    }

    return $findings.ToArray()
}
