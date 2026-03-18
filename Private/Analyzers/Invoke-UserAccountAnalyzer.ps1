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
    # CIS Benchmark 6.2.2: "Ensure root is the only UID 0 account"
    # ----------------------------------------------------------------
    $uid0Accounts = $passwdEntries | Where-Object { $_.UID -eq 0 -and $_.Username -ne 'root' }
    foreach ($acct in $uid0Accounts) {
        $findings.Add((New-Finding `
            -Id 'ACCT-001' `
            -Severity 'Critical' `
            -Category $analyzerCategory `
            -Title "Non-root account with UID 0: $($acct.Username)" `
            -Description "Account '$($acct.Username)' has UID 0, granting full root-equivalent privileges. Per CIS Benchmark 6.2.2, only the 'root' account should have UID 0. Additional UID 0 accounts bypass sudo audit controls, are invisible to many monitoring tools that only track 'root', and are a well-known persistence technique used by attackers to maintain backdoor access." `
            -ArtifactPath $passwdPath `
            -Evidence @($acct.RawLine) `
            -Recommendation "Remove the UID 0 assignment per CIS 6.2.2 or disable the account: usermod -L $($acct.Username). Investigate whether this account was created legitimately or is an indicator of compromise. Check creation timestamps and correlate with security events." `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '9.8' `
            -TechnicalImpact "Provides full root-equivalent privileges to '$($acct.Username)', bypassing sudo audit controls. This is a common attacker persistence technique (backdoor account)."
        ))
    }

    # ----------------------------------------------------------------
    # ACCT-002 (Critical): Accounts with empty password field in shadow
    # CIS Benchmark 6.2.1: "Ensure accounts in /etc/passwd use shadowed passwords"
    # ----------------------------------------------------------------
    foreach ($username in $shadowMap.Keys) {
        $hash = $shadowMap[$username].Hash
        # Empty password: the hash field is literally empty string or just ""
        if ($hash -eq '' -or $hash -eq '""') {
            $findings.Add((New-Finding `
                -Id 'ACCT-002' `
                -Severity 'Critical' `
                -Category $analyzerCategory `
                -Title "Account with empty password: $username" `
                -Description "Account '$username' has an empty password field in /etc/shadow, allowing login without any password. Per CIS Benchmark 6.2.1, all accounts must use shadowed passwords. An empty password field means anyone can authenticate as this user locally or via any service that uses PAM (SSH with PermitEmptyPasswords, FTP, web applications, etc.)." `
                -ArtifactPath $shadowPath `
                -Evidence @("$($username)::<remaining fields redacted>") `
                -Recommendation "Lock the account immediately: passwd -l $username. Then investigate whether this was intentional or indicates compromise. Set a strong password if the account is needed." `
                -MITRE $mitreShadowFile `
                -CVSSv3Score '9.8' `
                -TechnicalImpact "Allows unauthenticated login as '$username' without any password. If SSH PermitEmptyPasswords is enabled, this provides unauthenticated remote access."
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
    # CIS Benchmark 5.4.4: "Ensure default group for the root account is GID 0"
    # Reference: NIST SP 800-132 recommends strong KDFs (bcrypt, scrypt, Argon2)
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
                -Description "Account '$username' uses the weak $weakAlgorithm hashing algorithm. MD5 hashes can be cracked at billions of attempts per second on modern GPUs (hashcat benchmark: ~30 billion MD5/s). Modern systems should use SHA-512 (`$6`$) or yescrypt (`$y`$) which are computationally expensive and designed to resist GPU-accelerated cracking." `
                -ArtifactPath $shadowPath `
                -Evidence @("$username uses $weakAlgorithm (hash prefix: $hashPrefix)") `
                -Recommendation "Force a password change to rehash with a stronger algorithm: passwd $username. Update /etc/login.defs ENCRYPT_METHOD to SHA512 or YESCRYPT per CIS Benchmark recommendations." `
                -MITRE $mitreShadowFile `
                -CVSSv3Score '7.5' `
                -TechnicalImpact 'Weak password hashing algorithm enables rapid offline brute-force cracking of password hashes, potentially exposing account credentials.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # ACCT-007 (Medium): Duplicate UIDs
    # CIS Benchmark 6.2.16: "Ensure no duplicate UIDs exist"
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
            -Description "Multiple accounts share UID $uid ($usernames). Per CIS Benchmark 6.2.16, each account must have a unique UID. Duplicate UIDs cause file ownership ambiguity, make audit log attribution unreliable, and can mask unauthorized access." `
            -ArtifactPath $passwdPath `
            -Evidence @($evidenceLines) `
            -Recommendation 'Assign unique UIDs to each account. Investigate whether duplicate UIDs were intentionally configured or indicate compromise.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Duplicate UIDs allow multiple accounts to share the same privileges, complicating auditing and potentially masking unauthorized access.'
        ))
    }

    # ----------------------------------------------------------------
    # ACCT-008: Password policy weaknesses in /etc/login.defs
    # CIS Benchmark 5.4.1.1: "Ensure password expiration is 365 days or less"
    # CIS Benchmark 5.4.1.2: "Ensure minimum days between password changes"
    # CIS Benchmark 5.4.1.4: "Ensure inactive password lock is 30 days or less"
    # ----------------------------------------------------------------
    $loginDefsPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/login.defs'
    if (Test-Path $loginDefsPath -PathType Leaf) {
        $loginDefsLines = Read-ArtifactContent -Path $loginDefsPath
        $loginDefs = @{}
        foreach ($line in $loginDefsLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
            if ($trimmed -match '^\s*(\S+)\s+(.+)$') {
                $loginDefs[$Matches[1]] = $Matches[2].Trim()
            }
        }

        $policyIssues = @()

        if ($loginDefs.ContainsKey('PASS_MAX_DAYS')) {
            $maxDays = [int]$loginDefs['PASS_MAX_DAYS']
            if ($maxDays -gt 365 -or $maxDays -eq 99999) {
                $policyIssues += "PASS_MAX_DAYS = $maxDays (passwords never/rarely expire)"
            }
        }
        if ($loginDefs.ContainsKey('PASS_MIN_DAYS')) {
            $minDays = [int]$loginDefs['PASS_MIN_DAYS']
            if ($minDays -eq 0) {
                $policyIssues += "PASS_MIN_DAYS = 0 (no minimum password age)"
            }
        }
        if ($loginDefs.ContainsKey('PASS_MIN_LEN')) {
            $minLen = [int]$loginDefs['PASS_MIN_LEN']
            if ($minLen -lt 8) {
                $policyIssues += "PASS_MIN_LEN = $minLen (minimum length below 8)"
            }
        }
        if ($loginDefs.ContainsKey('ENCRYPT_METHOD')) {
            $method = $loginDefs['ENCRYPT_METHOD']
            if ($method -in @('DES', 'MD5')) {
                $policyIssues += "ENCRYPT_METHOD = $method (weak hash algorithm)"
            }
        }
        elseif ($loginDefs.ContainsKey('MD5_CRYPT_ENAB') -and $loginDefs['MD5_CRYPT_ENAB'] -eq 'yes') {
            $policyIssues += "MD5_CRYPT_ENAB = yes (MD5 hashing enabled)"
        }

        if ($policyIssues.Count -gt 0) {
            $findings.Add((New-Finding `
                -Id 'ACCT-008' `
                -Severity 'Medium' `
                -Category $analyzerCategory `
                -Title 'Weak password policy in /etc/login.defs' `
                -Description "Password policy weaknesses detected in /etc/login.defs: $($policyIssues.Count) issue(s) found." `
                -ArtifactPath $loginDefsPath `
                -Evidence $policyIssues `
                -Recommendation 'Update /etc/login.defs per CIS Benchmarks: PASS_MAX_DAYS=365 (CIS 5.4.1.1), PASS_MIN_DAYS=1 (CIS 5.4.1.2), PASS_MIN_LEN=14, ENCRYPT_METHOD=SHA512 or YESCRYPT.' `
                -MITRE $mitreValidAccounts `
                -CVSSv3Score '5.3' `
                -TechnicalImpact 'Weak password policies increase the risk of credential compromise through brute-force attacks or use of weak passwords.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # ACCT-009: Users in sensitive groups
    # ----------------------------------------------------------------
    $sensitiveGroups = @('docker', 'lxd', 'lxc', 'disk', 'adm', 'shadow', 'video', 'kmem', 'staff')

    # Parse /etc/group
    $groupMemberships = @{}
    foreach ($line in $groupLines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
        $fields = $trimmed.Split(':')
        if ($fields.Count -lt 4) { continue }
        $groupName = $fields[0]
        $members = $fields[3] -split ','

        if ($groupName -in $sensitiveGroups -and $members.Count -gt 0) {
            $validMembers = $members | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($validMembers.Count -gt 0) {
                $groupMemberships[$groupName] = $validMembers
            }
        }
    }

    foreach ($group in $groupMemberships.Keys) {
        $members = $groupMemberships[$group]
        $severity = if ($group -in @('docker', 'lxd', 'lxc', 'disk')) { 'High' } else { 'Medium' }
        $cvss = if ($severity -eq 'High') { '7.8' } else { '5.3' }

        $findings.Add((New-Finding `
            -Id 'ACCT-009' `
            -Severity $severity `
            -Category $analyzerCategory `
            -Title "Users in sensitive group '$group': $($members -join ', ')" `
            -Description "User(s) $($members -join ', ') are members of the '$group' group. $(switch ($group) { 'docker' { 'Docker group membership is equivalent to root access.' } 'lxd' { 'LXD group allows creating privileged containers for host escape.' } 'disk' { 'Disk group grants raw access to all block devices.' } 'shadow' { 'Shadow group can read password hashes.' } default { 'This group grants elevated privileges.' } })" `
            -ArtifactPath $groupPath `
            -Evidence @("Group: $group", "Members: $($members -join ', ')") `
            -Recommendation "Review group membership. Remove users from '$group' unless required for their role." `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score $cvss `
            -TechnicalImpact "Membership in the '$group' group grants elevated privileges that can be leveraged for privilege escalation."
        ))
    }

    # ----------------------------------------------------------------
    # ACCT-010: Accounts that have never logged in but have interactive shells
    # ----------------------------------------------------------------
    $lastlogPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'var/log/lastlog'
    $lastlogOutput = @()
    foreach ($pattern in @('lastlog*', 'last_login*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $lastlogOutput += $f }
    }

    if ($lastlogOutput.Count -gt 0) {
        $neverLoggedIn = @()
        foreach ($logFile in $lastlogOutput) {
            $lines = Read-ArtifactContent -Path $logFile.FullName
            foreach ($line in $lines) {
                if ($line -match '^\s*(\S+)\s+\*\*Never logged in\*\*') {
                    $username = $Matches[1]
                    # Check if this user has an interactive shell
                    $userEntry = $passwdEntries | Where-Object { $_.Username -eq $username }
                    if ($userEntry -and $userEntry.Shell -in $interactiveShells -and $userEntry.UID -ge 1000) {
                        $neverLoggedIn += $username
                    }
                }
            }
        }

        if ($neverLoggedIn.Count -gt 0) {
            $findings.Add((New-Finding `
                -Id 'ACCT-010' `
                -Severity 'Low' `
                -Category $analyzerCategory `
                -Title "Accounts with shells that never logged in ($($neverLoggedIn.Count))" `
                -Description "Found $($neverLoggedIn.Count) user account(s) with interactive shells that have never logged in. These may be orphaned or unused accounts." `
                -ArtifactPath ($lastlogOutput[0].FullName) `
                -Evidence @("Never-logged-in accounts with shells: $($neverLoggedIn -join ', ')") `
                -Recommendation 'Disable or remove unused accounts. Set shell to /usr/sbin/nologin for accounts that should not log in.' `
                -MITRE $mitreValidAccounts `
                -CVSSv3Score '2.6' `
                -TechnicalImpact 'Unused accounts with interactive shells increase the attack surface and may be targeted for credential compromise.'
            ))
        }
    }

    return $findings.ToArray()
}
