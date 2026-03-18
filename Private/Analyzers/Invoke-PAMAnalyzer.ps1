function Invoke-PAMAnalyzer {
    <#
    .SYNOPSIS
        Analyzes PAM configuration files for security issues.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Get all PAM config files
    $pamFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc/pam.d' -Recurse
    if ($pamFiles.Count -eq 0) {
        return @()
    }

    foreach ($pamFile in $pamFiles) {
        $lines = Read-ArtifactContent -Path $pamFile.FullName
        $fileName = $pamFile.Name
        $lineNum = 0

        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            # Check for pam_permit used without proper controls (allows auth without password)
            if ($trimmed -match 'pam_permit\.so') {
                # pam_permit in auth is dangerous
                if ($trimmed -match '^\s*(auth|account)\s+(required|sufficient|requisite)?\s+pam_permit') {
                    $findings.Add((New-Finding -Id "PAM-001" -Severity "High" -Category "Authentication" `
                        -Title "pam_permit allows passwordless authentication" `
                        -Description "pam_permit.so in $fileName grants access without authentication. This could allow any user to authenticate without a password." `
                        -ArtifactPath "/etc/pam.d/$fileName" `
                        -Evidence @("Line ${lineNum}: $trimmed") `
                        -Recommendation "Replace pam_permit.so with proper authentication modules (pam_unix, pam_deny)" `
                        -MITRE "T1556.003" `
                        -CVSSv3Score "8.6" `
                        -TechnicalImpact "Allows any user to authenticate without a password, enabling unauthorized access to the system or privilege escalation."))
                }
            }

            # Check for pam_exec (can be used as a backdoor)
            if ($trimmed -match 'pam_exec\.so') {
                $findings.Add((New-Finding -Id "PAM-002" -Severity "High" -Category "Persistence" `
                    -Title "pam_exec module configured - potential backdoor" `
                    -Description "pam_exec.so in $fileName executes an external command during PAM authentication. This can be used as a persistence mechanism." `
                    -ArtifactPath "/etc/pam.d/$fileName" `
                    -Evidence @("Line ${lineNum}: $trimmed") `
                    -Recommendation "Verify the command executed by pam_exec.so is legitimate and expected" `
                    -MITRE "T1556.003" `
                    -CVSSv3Score "8.4" `
                    -TechnicalImpact "Allows execution of arbitrary commands during authentication, enabling credential harvesting, backdoor access, or persistent code execution."))
            }

            # Check for missing account lockout (no pam_faillock or pam_tally)
            if ($fileName -eq 'common-auth' -or $fileName -eq 'system-auth' -or $fileName -eq 'login') {
                if ($trimmed -match '^\s*auth\s+' -and $trimmed -notmatch 'pam_faillock|pam_tally|pam_faildelay') {
                    # We'll flag this at file level below
                }
            }

            # Check for pam_rootok without restrictions
            if ($trimmed -match 'pam_rootok\.so' -and $trimmed -match '^\s*auth\s+sufficient') {
                $findings.Add((New-Finding -Id "PAM-003" -Severity "Medium" -Category "Authentication" `
                    -Title "pam_rootok allows root bypass in $fileName" `
                    -Description "pam_rootok.so as sufficient auth means root can bypass all other authentication checks in this service." `
                    -ArtifactPath "/etc/pam.d/$fileName" `
                    -Evidence @("Line ${lineNum}: $trimmed") `
                    -Recommendation "Ensure pam_rootok is only used in appropriate services (su, sudo)" `
                    -MITRE "T1548.003" `
                    -CVSSv3Score "6.7" `
                    -TechnicalImpact "Root can bypass authentication checks for this service, which may be exploited if root access is partially compromised or misconfigured."))
            }

            # Check for nullok (allows empty passwords)
            if ($trimmed -match 'nullok' -and $trimmed -match '^\s*auth\s+') {
                $findings.Add((New-Finding -Id "PAM-004" -Severity "Medium" -Category "Authentication" `
                    -Title "Null/empty passwords allowed in $fileName" `
                    -Description "The 'nullok' option allows accounts with empty password fields to authenticate." `
                    -ArtifactPath "/etc/pam.d/$fileName" `
                    -Evidence @("Line ${lineNum}: $trimmed") `
                    -Recommendation "Remove 'nullok' option to prevent empty password authentication" `
                    -MITRE "T1078" `
                    -CVSSv3Score "6.5" `
                    -TechnicalImpact "Accounts with empty passwords can authenticate, enabling unauthorized access without any credential knowledge."))
            }
        }
    }

    # Check if account lockout is configured
    $authFiles = $pamFiles | Where-Object { $_.Name -in @('common-auth', 'system-auth', 'login', 'sshd') }
    foreach ($authFile in $authFiles) {
        $content = (Read-ArtifactContent -Path $authFile.FullName) -join "`n"
        if ($content -notmatch 'pam_faillock|pam_tally') {
            $findings.Add((New-Finding -Id "PAM-005" -Severity "Medium" -Category "Authentication" `
                -Title "No account lockout configured in $($authFile.Name)" `
                -Description "Neither pam_faillock nor pam_tally2 is configured, meaning there is no protection against brute force attacks at the PAM level." `
                -ArtifactPath "/etc/pam.d/$($authFile.Name)" `
                -Evidence @("No pam_faillock or pam_tally module found") `
                -Recommendation "Configure pam_faillock to lock accounts after repeated failed login attempts" `
                -MITRE "T1110" `
                -CVSSv3Score "5.3" `
                -TechnicalImpact "Without account lockout, attackers can perform unlimited brute-force password attempts against user accounts."))
        }
    }

    # ----------------------------------------------------------------
    # PAM-007: Passwords in PAM configuration files
    # ----------------------------------------------------------------
    foreach ($pamFile in $pamFiles) {
        $lines = Read-ArtifactContent -Path $pamFile.FullName
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            # Check for hardcoded passwords in PAM configs
            if ($trimmed -match '(?i)(password|passwd|secret)\s*=\s*\S+' -and $trimmed -notmatch 'pam_unix|pam_pwquality|pam_cracklib') {
                $findings.Add((New-Finding -Id "PAM-007" -Severity "High" -Category "Authentication" `
                    -Title "Password found in PAM configuration: $($pamFile.Name)" `
                    -Description "A hardcoded password or secret was found in PAM configuration file '$($pamFile.Name)' at line $lineNum." `
                    -ArtifactPath "/etc/pam.d/$($pamFile.Name)" `
                    -Evidence @("Line ${lineNum}: <password redacted>") `
                    -Recommendation "Remove hardcoded passwords from PAM configurations. Use secure credential storage mechanisms." `
                    -MITRE "T1552.001" `
                    -CVSSv3Score "7.5" `
                    -TechnicalImpact "Hardcoded passwords in PAM configuration files can be read by any user with access to /etc/pam.d, enabling credential theft."))
            }
        }
    }

    # ----------------------------------------------------------------
    # PAM-008: pam_cap.so loaded (capability-based privilege escalation)
    # ----------------------------------------------------------------
    foreach ($pamFile in $pamFiles) {
        $lines = Read-ArtifactContent -Path $pamFile.FullName
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            if ($trimmed -match 'pam_cap\.so') {
                $findings.Add((New-Finding -Id "PAM-008" -Severity "Medium" -Category "Authentication" `
                    -Title "pam_cap.so loaded in $($pamFile.Name)" `
                    -Description "pam_cap.so is configured in '$($pamFile.Name)', enabling capability-based privilege assignment during login. Users may receive elevated capabilities defined in /etc/security/capability.conf." `
                    -ArtifactPath "/etc/pam.d/$($pamFile.Name)" `
                    -Evidence @("Line ${lineNum}: $trimmed") `
                    -Recommendation "Review /etc/security/capability.conf for overly permissive capability assignments. Ensure only authorized users receive elevated capabilities." `
                    -MITRE "T1548.001" `
                    -CVSSv3Score "6.5" `
                    -TechnicalImpact "pam_cap.so assigns Linux capabilities to users at login, potentially granting elevated privileges that bypass standard permission controls."))
            }
        }
    }

    # Informational summary
    $findings.Add((New-Finding -Id "PAM-INFO" -Severity "Informational" -Category "Authentication" `
        -Title "PAM configuration summary" `
        -Description "Found $($pamFiles.Count) PAM configuration files in /etc/pam.d/." `
        -ArtifactPath "/etc/pam.d/" `
        -Evidence @($pamFiles | ForEach-Object { $_.Name }) `
        -Recommendation "Review PAM configuration for compliance with organizational policy" `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    return $findings.ToArray()
}
