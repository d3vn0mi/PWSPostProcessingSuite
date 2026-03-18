function Invoke-WinUserAccountAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows user accounts and group membership for security issues.
    .DESCRIPTION
        Examines collected Windows user account data including local users, group
        memberships, password policies, and account flags to identify security
        misconfigurations such as enabled built-in accounts, weak password policies,
        excessive admin privileges, and accounts with PasswordNotRequired flag.
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
    $analyzerCategory = 'Windows User Accounts'
    $mitreValidAccounts = 'T1078'

    # ----------------------------------------------------------------
    # Load artifacts
    # ----------------------------------------------------------------
    $usersDir = Join-Path $EvidencePath 'users'
    $commandsDir = Join-Path $EvidencePath 'collected_commands'

    # Try CSV first, fall back to TXT for local users
    $localUsersPath = $null
    $localUsersCsv = Join-Path $usersDir 'local_users.csv'
    $localUsersTxt = Join-Path $usersDir 'local_users.txt'
    if (Test-Path $localUsersCsv) { $localUsersPath = $localUsersCsv }
    elseif (Test-Path $localUsersTxt) { $localUsersPath = $localUsersTxt }

    # Try CSV first, fall back to TXT for local groups
    $localGroupsPath = $null
    $localGroupsCsv = Join-Path $usersDir 'local_groups.csv'
    $localGroupsTxt = Join-Path $usersDir 'local_groups.txt'
    if (Test-Path $localGroupsCsv) { $localGroupsPath = $localGroupsCsv }
    elseif (Test-Path $localGroupsTxt) { $localGroupsPath = $localGroupsTxt }

    $adminsGroupPath = Join-Path $usersDir 'administrators_group.txt'
    $netAccountsPath = Join-Path $commandsDir 'net_accounts.txt'
    $whoamiPath = Join-Path $commandsDir 'whoami_all.txt'

    if (-not $localUsersPath -or -not (Test-Path $localUsersPath)) {
        Write-Verbose "WinUserAccountAnalyzer: No local users data found, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Parse local users
    # ----------------------------------------------------------------
    $users = [System.Collections.Generic.List[hashtable]]::new()

    if ($localUsersPath -like '*.csv') {
        try {
            $csvData = Import-Csv -Path $localUsersPath
            foreach ($row in $csvData) {
                $user = @{
                    Name               = if ($row.Name) { $row.Name } elseif ($row.Username) { $row.Username } else { '' }
                    Enabled            = $false
                    PasswordExpires    = $true
                    LastLogon          = ''
                    PasswordNotRequired = $false
                    Description        = ''
                    SID                = ''
                    RawLine            = ''
                }
                # Parse Enabled field
                if ($row.Enabled) {
                    $user.Enabled = $row.Enabled -match '(?i)^(true|yes|1)$'
                }
                # Parse PasswordExpires
                if ($row.PasswordExpires -match '(?i)^(false|no|0|never)$') {
                    $user.PasswordExpires = $false
                }
                # Parse LastLogon
                if ($row.LastLogon) { $user.LastLogon = $row.LastLogon }
                # Parse PasswordNotRequired
                if ($row.PasswordNotRequired -match '(?i)^(true|yes|1)$') {
                    $user.PasswordNotRequired = $true
                }
                if ($row.Description) { $user.Description = $row.Description }
                if ($row.SID) { $user.SID = $row.SID }
                $user.RawLine = ($row.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                $users.Add($user)
            }
        }
        catch {
            Write-Verbose "WinUserAccountAnalyzer: Failed to parse CSV: $_"
        }
    }
    else {
        # Parse text format - expect lines like "Name = value" or tabular output
        $content = Get-Content -Path $localUsersPath -ErrorAction SilentlyContinue
        $currentUser = $null
        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($currentUser -and $currentUser.Name) {
                    $users.Add($currentUser)
                    $currentUser = $null
                }
                continue
            }
            if ($trimmed -match '^\s*Name\s*[=:]\s*(.+)$') {
                if ($currentUser -and $currentUser.Name) { $users.Add($currentUser) }
                $currentUser = @{
                    Name = $Matches[1].Trim(); Enabled = $false; PasswordExpires = $true
                    LastLogon = ''; PasswordNotRequired = $false; Description = ''; SID = ''
                    RawLine = $trimmed
                }
            }
            elseif ($currentUser) {
                if ($trimmed -match '^\s*Enabled\s*[=:]\s*(.+)$') {
                    $currentUser.Enabled = $Matches[1].Trim() -match '(?i)^(true|yes|1)$'
                }
                elseif ($trimmed -match '^\s*PasswordExpires\s*[=:]\s*(.+)$') {
                    $val = $Matches[1].Trim()
                    if ($val -match '(?i)^(false|no|0|never)$') { $currentUser.PasswordExpires = $false }
                }
                elseif ($trimmed -match '^\s*LastLogon\s*[=:]\s*(.+)$') {
                    $currentUser.LastLogon = $Matches[1].Trim()
                }
                elseif ($trimmed -match '^\s*PasswordNotRequired\s*[=:]\s*(.+)$') {
                    $currentUser.PasswordNotRequired = $Matches[1].Trim() -match '(?i)^(true|yes|1)$'
                }
                elseif ($trimmed -match '^\s*Description\s*[=:]\s*(.+)$') {
                    $currentUser.Description = $Matches[1].Trim()
                }
                elseif ($trimmed -match '^\s*SID\s*[=:]\s*(.+)$') {
                    $currentUser.SID = $Matches[1].Trim()
                }
                $currentUser.RawLine += "; $trimmed"
            }
        }
        if ($currentUser -and $currentUser.Name) { $users.Add($currentUser) }
    }

    if ($users.Count -eq 0) {
        Write-Verbose "WinUserAccountAnalyzer: No users parsed from evidence, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Parse administrators group membership
    # ----------------------------------------------------------------
    $adminMembers = [System.Collections.Generic.List[string]]::new()
    if (Test-Path $adminsGroupPath) {
        $adminContent = Get-Content -Path $adminsGroupPath -ErrorAction SilentlyContinue
        foreach ($line in $adminContent) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            # Skip header lines
            if ($trimmed -match '(?i)^(Alias|Comment|Members|---|-{2,})') { continue }
            if ($trimmed -match '(?i)^The command completed') { continue }
            # Each remaining non-empty line is a member
            $adminMembers.Add($trimmed)
        }
    }

    # Standard admin accounts that are expected
    $standardAdminAccounts = @('Administrator', 'Domain Admins', 'Enterprise Admins')

    # ----------------------------------------------------------------
    # Parse net accounts output for password policy
    # ----------------------------------------------------------------
    $passwordPolicy = @{
        MinLength       = -1
        MaxAge          = -1
        MinAge          = -1
        LockoutThreshold = -1
        LockoutDuration = -1
        ComplexityEnabled = $true  # Assume true unless evidence says otherwise
    }

    if (Test-Path $netAccountsPath) {
        $netAccountsContent = Get-Content -Path $netAccountsPath -ErrorAction SilentlyContinue
        foreach ($line in $netAccountsContent) {
            $trimmed = $line.Trim()
            if ($trimmed -match '(?i)Minimum\s+password\s+length\s*[=:]\s*(\d+)') {
                $passwordPolicy.MinLength = [int]$Matches[1]
            }
            elseif ($trimmed -match '(?i)Maximum\s+password\s+age\s*[=:]\s*(.+)$') {
                $val = $Matches[1].Trim()
                if ($val -match '(?i)unlimited|never') {
                    $passwordPolicy.MaxAge = 0
                }
                elseif ($val -match '(\d+)') {
                    $passwordPolicy.MaxAge = [int]$Matches[1]
                }
            }
            elseif ($trimmed -match '(?i)Minimum\s+password\s+age\s*[=:]\s*(\d+)') {
                $passwordPolicy.MinAge = [int]$Matches[1]
            }
            elseif ($trimmed -match '(?i)Lockout\s+threshold\s*[=:]\s*(.+)$') {
                $val = $Matches[1].Trim()
                if ($val -match '(?i)never') {
                    $passwordPolicy.LockoutThreshold = 0
                }
                elseif ($val -match '(\d+)') {
                    $passwordPolicy.LockoutThreshold = [int]$Matches[1]
                }
            }
            elseif ($trimmed -match '(?i)Lockout\s+duration\s*[=:]\s*(\d+)') {
                $passwordPolicy.LockoutDuration = [int]$Matches[1]
            }
        }
    }

    # Check security policy for complexity
    $secPolicyPath = Join-Path $EvidencePath 'security'
    if (Test-Path $secPolicyPath) {
        $secFiles = Get-ChildItem -Path $secPolicyPath -File -ErrorAction SilentlyContinue
        foreach ($secFile in $secFiles) {
            $secContent = Get-Content -Path $secFile.FullName -ErrorAction SilentlyContinue
            foreach ($line in $secContent) {
                if ($line -match '(?i)PasswordComplexity\s*=\s*(\d+)') {
                    if ([int]$Matches[1] -eq 0) {
                        $passwordPolicy.ComplexityEnabled = $false
                    }
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # WACCT-001 (Critical): Built-in Administrator account is enabled
    # ----------------------------------------------------------------
    $builtinAdmin = $users | Where-Object {
        ($_.Name -eq 'Administrator' -or ($_.SID -and $_.SID -match '-500$'))
    }
    foreach ($admin in $builtinAdmin) {
        if ($admin.Enabled) {
            $findings.Add((New-Finding `
                -Id 'WACCT-001' `
                -Severity 'Critical' `
                -Category $analyzerCategory `
                -Title 'Built-in Administrator account is enabled' `
                -Description "The built-in Administrator account is enabled. This well-known account is a primary target for brute-force attacks and should be disabled in favor of named admin accounts." `
                -ArtifactPath $localUsersPath `
                -Evidence @("Account: $($admin.Name)", "Enabled: True", "SID: $($admin.SID)") `
                -Recommendation 'Disable the built-in Administrator account and use named individual admin accounts. Rename the account if it cannot be disabled.' `
                -MITRE $mitreValidAccounts `
                -CVSSv3Score '9.8' `
                -TechnicalImpact 'The built-in Administrator account has full system privileges and is a well-known target. If compromised, complete system takeover is possible.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # WACCT-002 (High): Guest account is enabled
    # ----------------------------------------------------------------
    $guestAccount = $users | Where-Object {
        ($_.Name -eq 'Guest' -or ($_.SID -and $_.SID -match '-501$'))
    }
    foreach ($guest in $guestAccount) {
        if ($guest.Enabled) {
            $findings.Add((New-Finding `
                -Id 'WACCT-002' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title 'Guest account is enabled' `
                -Description "The built-in Guest account is enabled. This allows unauthenticated access to the system with limited privileges, which can be leveraged for initial access." `
                -ArtifactPath $localUsersPath `
                -Evidence @("Account: $($guest.Name)", "Enabled: True") `
                -Recommendation 'Disable the Guest account: net user Guest /active:no' `
                -MITRE $mitreValidAccounts `
                -CVSSv3Score '7.5' `
                -TechnicalImpact 'The Guest account provides unauthenticated access to the system, enabling reconnaissance and potential privilege escalation.'
            ))
        }
    }

    # ----------------------------------------------------------------
    # WACCT-003 (High): Non-standard accounts in Administrators group
    # ----------------------------------------------------------------
    $nonStandardAdmins = @()
    foreach ($member in $adminMembers) {
        $isStandard = $false
        foreach ($std in $standardAdminAccounts) {
            if ($member -match [regex]::Escape($std)) {
                $isStandard = $true
                break
            }
        }
        if (-not $isStandard) {
            $nonStandardAdmins += $member
        }
    }

    if ($nonStandardAdmins.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WACCT-003' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title "Non-standard accounts in Administrators group ($($nonStandardAdmins.Count))" `
            -Description "Found $($nonStandardAdmins.Count) non-standard account(s) in the local Administrators group. Each admin account increases the attack surface." `
            -ArtifactPath $adminsGroupPath `
            -Evidence @($nonStandardAdmins | ForEach-Object { "Member: $_" }) `
            -Recommendation 'Review all Administrators group members. Remove accounts that do not require administrative access. Use least-privilege principles.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '7.8' `
            -TechnicalImpact 'Non-standard admin accounts increase the attack surface. Compromising any one provides full system control.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-004 (Medium): Accounts that never expire
    # ----------------------------------------------------------------
    $neverExpireAccounts = @()
    foreach ($user in $users) {
        if ($user.Enabled -and -not $user.PasswordExpires) {
            # Skip built-in service-type accounts
            if ($user.Name -notin @('DefaultAccount', 'WDAGUtilityAccount', 'Guest')) {
                $neverExpireAccounts += $user.Name
            }
        }
    }

    if ($neverExpireAccounts.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WACCT-004' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Accounts with non-expiring passwords ($($neverExpireAccounts.Count))" `
            -Description "Found $($neverExpireAccounts.Count) enabled account(s) with passwords set to never expire. Non-expiring passwords increase the window for credential-based attacks." `
            -ArtifactPath $localUsersPath `
            -Evidence @($neverExpireAccounts | ForEach-Object { "Account: $_ - PasswordExpires: False" }) `
            -Recommendation 'Configure password expiration policies. Set maximum password age to 90 days or less via Group Policy.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Non-expiring passwords provide an indefinite window for credential attacks, allowing compromised credentials to remain valid indefinitely.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-005 (Medium): Weak password policy
    # ----------------------------------------------------------------
    $policyIssues = @()
    if ($passwordPolicy.MinLength -ge 0 -and $passwordPolicy.MinLength -lt 8) {
        $policyIssues += "Minimum password length: $($passwordPolicy.MinLength) (should be >= 8)"
    }
    if ($passwordPolicy.MaxAge -eq 0) {
        $policyIssues += "Maximum password age: Unlimited (passwords never expire)"
    }
    if (-not $passwordPolicy.ComplexityEnabled) {
        $policyIssues += "Password complexity: Disabled (should be enabled)"
    }

    if ($policyIssues.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WACCT-005' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Weak password policy detected ($($policyIssues.Count) issue(s))" `
            -Description "The system password policy has $($policyIssues.Count) weakness(es) that could allow users to set weak passwords." `
            -ArtifactPath $netAccountsPath `
            -Evidence $policyIssues `
            -Recommendation 'Configure strong password policy via Group Policy: minimum length 14+, complexity enabled, maximum age 90 days, minimum age 1 day.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Weak password policies allow users to set easily guessable passwords, enabling brute-force and credential stuffing attacks.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-006 (Medium): Users that have never logged in but are enabled
    # ----------------------------------------------------------------
    $neverLoggedIn = @()
    foreach ($user in $users) {
        if ($user.Enabled -and $user.Name -notin @('DefaultAccount', 'WDAGUtilityAccount', 'Guest')) {
            $lastLogon = $user.LastLogon
            if ([string]::IsNullOrWhiteSpace($lastLogon) -or $lastLogon -match '(?i)^(never|$)' -or $lastLogon -match '^\s*$') {
                $neverLoggedIn += $user.Name
            }
        }
    }

    if ($neverLoggedIn.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WACCT-006' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Enabled accounts that have never logged in ($($neverLoggedIn.Count))" `
            -Description "Found $($neverLoggedIn.Count) enabled account(s) that have never logged in. These may be orphaned or provisioned but unused accounts." `
            -ArtifactPath $localUsersPath `
            -Evidence @($neverLoggedIn | ForEach-Object { "Account: $_ - LastLogon: Never" }) `
            -Recommendation 'Disable or remove unused accounts. Investigate why these accounts exist and whether they are needed.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Unused enabled accounts increase the attack surface and may be targeted for credential compromise or unauthorized access.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-007 (Low): No account lockout policy configured
    # ----------------------------------------------------------------
    if ($passwordPolicy.LockoutThreshold -eq 0) {
        $findings.Add((New-Finding `
            -Id 'WACCT-007' `
            -Severity 'Low' `
            -Category $analyzerCategory `
            -Title 'No account lockout policy configured' `
            -Description "The account lockout threshold is set to 0 (never lockout) or not configured. This allows unlimited password guessing attempts." `
            -ArtifactPath $netAccountsPath `
            -Evidence @("Lockout threshold: $($passwordPolicy.LockoutThreshold) (Never)") `
            -Recommendation 'Configure account lockout policy: Set lockout threshold to 5 attempts, lockout duration to 30 minutes, and reset counter after 30 minutes.' `
            -MITRE 'T1110' `
            -CVSSv3Score '3.7' `
            -TechnicalImpact 'Without account lockout, attackers can perform unlimited brute-force attempts against user accounts without detection or prevention.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-008 (Low): Multiple admin accounts
    # ----------------------------------------------------------------
    if ($adminMembers.Count -gt 3) {
        $findings.Add((New-Finding `
            -Id 'WACCT-008' `
            -Severity 'Low' `
            -Category $analyzerCategory `
            -Title "Multiple accounts in Administrators group ($($adminMembers.Count))" `
            -Description "The local Administrators group has $($adminMembers.Count) members. A large number of admin accounts increases the risk of credential compromise." `
            -ArtifactPath $adminsGroupPath `
            -Evidence @($adminMembers | ForEach-Object { "Member: $_" }) `
            -Recommendation 'Reduce the number of Administrators group members to the minimum required. Use least-privilege principles and consider Just-In-Time (JIT) admin access.' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '3.7' `
            -TechnicalImpact 'Excessive admin accounts increase the attack surface and make it harder to audit privileged access.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-009 (High): Accounts with PasswordNotRequired flag
    # ----------------------------------------------------------------
    $pwdNotRequired = @()
    foreach ($user in $users) {
        if ($user.Enabled -and $user.PasswordNotRequired) {
            $pwdNotRequired += $user.Name
        }
    }

    if ($pwdNotRequired.Count -gt 0) {
        $findings.Add((New-Finding `
            -Id 'WACCT-009' `
            -Severity 'High' `
            -Category $analyzerCategory `
            -Title "Accounts with PasswordNotRequired flag ($($pwdNotRequired.Count))" `
            -Description "Found $($pwdNotRequired.Count) enabled account(s) with the PasswordNotRequired flag set. These accounts can have blank passwords." `
            -ArtifactPath $localUsersPath `
            -Evidence @($pwdNotRequired | ForEach-Object { "Account: $_ - PasswordNotRequired: True" }) `
            -Recommendation 'Remove the PasswordNotRequired flag from all accounts: Set-LocalUser -Name <username> -PasswordNotRequired $false' `
            -MITRE $mitreValidAccounts `
            -CVSSv3Score '8.6' `
            -TechnicalImpact 'Accounts with PasswordNotRequired can have blank passwords, allowing unauthenticated access to the system.'
        ))
    }

    # ----------------------------------------------------------------
    # WACCT-010 (Informational): Account summary
    # ----------------------------------------------------------------
    $totalAccounts = $users.Count
    $enabledAccounts = @($users | Where-Object { $_.Enabled }).Count
    $disabledAccounts = $totalAccounts - $enabledAccounts
    $adminCount = $adminMembers.Count

    $summaryEvidence = @(
        "Total local accounts: $totalAccounts"
        "Enabled accounts: $enabledAccounts"
        "Disabled accounts: $disabledAccounts"
        "Administrators group members: $adminCount"
        "Accounts with non-expiring passwords: $($neverExpireAccounts.Count)"
        "Accounts with PasswordNotRequired: $($pwdNotRequired.Count)"
        "Accounts that never logged in: $($neverLoggedIn.Count)"
    )

    if ($passwordPolicy.MinLength -ge 0) {
        $summaryEvidence += "Password policy - Min length: $($passwordPolicy.MinLength)"
    }
    if ($passwordPolicy.MaxAge -ge 0) {
        $maxAgeStr = if ($passwordPolicy.MaxAge -eq 0) { 'Unlimited' } else { "$($passwordPolicy.MaxAge) days" }
        $summaryEvidence += "Password policy - Max age: $maxAgeStr"
    }
    $summaryEvidence += "Password policy - Complexity: $(if ($passwordPolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })"

    $findings.Add((New-Finding `
        -Id 'WACCT-010' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Windows user account summary' `
        -Description 'Summary of all local user accounts and security policy settings.' `
        -ArtifactPath $localUsersPath `
        -Evidence $summaryEvidence `
        -MITRE $mitreValidAccounts `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
