function Invoke-WinGroupPolicyAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows Group Policy and security audit configuration for misconfigurations.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ----------------------------------------------------------------
    # WGP-001: Audit policy with "No Auditing" for critical categories
    # ----------------------------------------------------------------
    $auditPolicyPath = Join-Path $EvidencePath 'security/audit_policy.txt'
    if (Test-Path $auditPolicyPath) {
        $auditLines = Read-ArtifactContent -Path $auditPolicyPath
        $criticalCategories = @('Logon/Logoff', 'Account Logon', 'Account Management', 'Object Access')
        $currentCategory = ''
        $noAuditFindings = @()

        foreach ($line in $auditLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            # Detect category headers (lines that are not indented and don't contain subcategory details)
            foreach ($cat in $criticalCategories) {
                if ($trimmed -match "^\s*$([regex]::Escape($cat))\s*$" -or $trimmed -eq $cat) {
                    $currentCategory = $cat
                    break
                }
            }

            # Detect subcategory lines with "No Auditing"
            if ($trimmed -match 'No Auditing' -and $currentCategory -ne '') {
                # Extract subcategory name
                if ($trimmed -match '^\s*(.+?)\s{2,}No Auditing') {
                    $subCategory = $Matches[1].Trim()
                    $noAuditFindings += "$currentCategory > $subCategory : No Auditing"
                }
            }

            # Reset category when we hit a non-critical category header
            if ($trimmed -notmatch '^\s' -and $trimmed -notmatch 'No Auditing|Success|Failure') {
                $isCritical = $false
                foreach ($cat in $criticalCategories) {
                    if ($trimmed -match [regex]::Escape($cat)) { $isCritical = $true; break }
                }
                if (-not $isCritical -and $trimmed -notmatch '^\s*$') {
                    $currentCategory = ''
                }
            }
        }

        if ($noAuditFindings.Count -gt 0) {
            $findings.Add((New-Finding -Id 'WGP-001' -Severity 'High' -Category 'Group Policy' `
                -Title 'Critical audit categories have No Auditing configured' `
                -Description "Found $($noAuditFindings.Count) critical audit subcategories with 'No Auditing'. This creates blind spots for detecting logon abuse, account manipulation, and object access attacks." `
                -ArtifactPath 'security/audit_policy.txt' `
                -Evidence @($noAuditFindings | Select-Object -First 10) `
                -Recommendation 'Enable Success and Failure auditing for all subcategories under Logon/Logoff, Account Logon, Account Management, and Object Access using auditpol or Group Policy.' `
                -MITRE 'T1562.002' `
                -CVSSv3Score '7.5' `
                -TechnicalImpact 'Disabled auditing on critical categories prevents detection of brute-force attacks, unauthorized logons, privilege escalation, and lateral movement.'))
        }
    }

    # ----------------------------------------------------------------
    # WGP-002: PowerShell Script Block Logging not enabled
    # WGP-003: PowerShell Module Logging not enabled
    # ----------------------------------------------------------------
    $gpresultPath = Join-Path $EvidencePath 'security/gpresult.txt'
    $gpresultContent = ''
    if (Test-Path $gpresultPath) {
        $gpresultLines = Read-ArtifactContent -Path $gpresultPath
        $gpresultContent = $gpresultLines -join "`n"
    }

    # Check for Script Block Logging
    $scriptBlockLoggingEnabled = $false
    if ($gpresultContent -match 'ScriptBlockLogging' -and $gpresultContent -match 'EnableScriptBlockLogging\s*[:=]\s*1') {
        $scriptBlockLoggingEnabled = $true
    }

    # Also check registry-based evidence in gpresult
    if (-not $scriptBlockLoggingEnabled -and $gpresultContent -match 'Turn on PowerShell Script Block Logging\s*[:=]?\s*Enabled') {
        $scriptBlockLoggingEnabled = $true
    }

    if (-not $scriptBlockLoggingEnabled) {
        $findings.Add((New-Finding -Id 'WGP-002' -Severity 'Medium' -Category 'Group Policy' `
            -Title 'PowerShell Script Block Logging not enabled' `
            -Description 'PowerShell Script Block Logging is not configured via Group Policy. This prevents capturing the full content of executed PowerShell scripts, including decoded and deobfuscated code blocks.' `
            -ArtifactPath 'security/gpresult.txt' `
            -Evidence @('ScriptBlockLogging policy not found or not enabled in gpresult output') `
            -Recommendation 'Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.' `
            -MITRE 'T1562.002' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Without Script Block Logging, obfuscated PowerShell attacks cannot be decoded and logged, reducing visibility into malicious script execution.'))
    }

    # Check for Module Logging
    $moduleLoggingEnabled = $false
    if ($gpresultContent -match 'ModuleLogging' -and $gpresultContent -match 'EnableModuleLogging\s*[:=]\s*1') {
        $moduleLoggingEnabled = $true
    }
    if (-not $moduleLoggingEnabled -and $gpresultContent -match 'Turn on Module Logging\s*[:=]?\s*Enabled') {
        $moduleLoggingEnabled = $true
    }

    if (-not $moduleLoggingEnabled) {
        $findings.Add((New-Finding -Id 'WGP-003' -Severity 'Medium' -Category 'Group Policy' `
            -Title 'PowerShell Module Logging not enabled' `
            -Description 'PowerShell Module Logging is not configured via Group Policy. Module Logging records pipeline execution details for specified modules, providing visibility into PowerShell usage.' `
            -ArtifactPath 'security/gpresult.txt' `
            -Evidence @('ModuleLogging policy not found or not enabled in gpresult output') `
            -Recommendation 'Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging. Set module names to * for comprehensive logging.' `
            -MITRE 'T1562.002' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Without Module Logging, PowerShell module invocations are not recorded, limiting forensic visibility into attacker tool usage and lateral movement scripts.'))
    }

    # ----------------------------------------------------------------
    # WGP-004: Credential Guard not enabled
    # ----------------------------------------------------------------
    $credGuardEnabled = $false
    if ($gpresultContent -match 'Credential Guard' -and $gpresultContent -match 'LsaCfgFlags\s*[:=]\s*[12]') {
        $credGuardEnabled = $true
    }
    if (-not $credGuardEnabled -and $gpresultContent -match 'Credential Guard\s*[:=]?\s*Enabled') {
        $credGuardEnabled = $true
    }

    # Also check security policy export
    $secPolicyPath = Join-Path $EvidencePath 'security/security_policy.cfg'
    $secPolicyContent = ''
    if (Test-Path $secPolicyPath) {
        $secPolicyLines = Read-ArtifactContent -Path $secPolicyPath
        $secPolicyContent = $secPolicyLines -join "`n"

        if (-not $credGuardEnabled -and $secPolicyContent -match 'LsaCfgFlags\s*=\s*[12]') {
            $credGuardEnabled = $true
        }
    }

    if (-not $credGuardEnabled) {
        $findings.Add((New-Finding -Id 'WGP-004' -Severity 'High' -Category 'Group Policy' `
            -Title 'Credential Guard not enabled' `
            -Description 'Windows Credential Guard (VBS-based credential isolation) is not enabled. Without Credential Guard, credentials stored in LSASS memory can be extracted by tools like Mimikatz.' `
            -ArtifactPath 'security/gpresult.txt' `
            -Evidence @('LsaCfgFlags not set to 1 or 2 in Group Policy or security policy') `
            -Recommendation 'Enable Credential Guard via GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn on Virtualization Based Security > Credential Guard Configuration.' `
            -MITRE 'T1003.001' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'LSASS memory is unprotected, allowing credential dumping tools to extract plaintext passwords, NTLM hashes, and Kerberos tickets for lateral movement.'))
    }

    # ----------------------------------------------------------------
    # WGP-005: LSA protection not enabled
    # ----------------------------------------------------------------
    $lsaProtectionEnabled = $false
    if ($gpresultContent -match 'RunAsPPL\s*[:=]\s*1') {
        $lsaProtectionEnabled = $true
    }
    if (-not $lsaProtectionEnabled -and $secPolicyContent -match 'RunAsPPL\s*=\s*1') {
        $lsaProtectionEnabled = $true
    }

    if (-not $lsaProtectionEnabled) {
        $findings.Add((New-Finding -Id 'WGP-005' -Severity 'High' -Category 'Group Policy' `
            -Title 'LSA protection (RunAsPPL) not enabled' `
            -Description 'LSA protection (Protected Process Light) is not enabled. Without RunAsPPL, the LSASS process is not protected from code injection and memory reading by non-protected processes.' `
            -ArtifactPath 'security/security_policy.cfg' `
            -Evidence @('RunAsPPL not set to 1 in Group Policy or security policy configuration') `
            -Recommendation 'Enable LSA protection by setting HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL to 1 via Group Policy or registry.' `
            -MITRE 'T1003.001' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'LSASS process runs without Protected Process Light, allowing attackers with admin access to inject code or read process memory for credential theft.'))
    }

    # ----------------------------------------------------------------
    # WGP-006: WinRM configuration issues
    # ----------------------------------------------------------------
    $winrmIssues = @()

    if ($gpresultContent -match 'AllowAutoConfig\s*[:=]\s*1' -or $gpresultContent -match 'Allow remote server management through WinRM\s*[:=]?\s*Enabled') {
        # WinRM is enabled - check for overly permissive configuration
        if ($gpresultContent -match 'IPv4Filter\s*[:=]\s*\*' -or $gpresultContent -match 'TrustedHosts\s*[:=]\s*\*') {
            $winrmIssues += 'WinRM configured to accept connections from all hosts (wildcard filter)'
        }
        if ($gpresultContent -match 'AllowUnencrypted\s*[:=]\s*1' -or $gpresultContent -match 'AllowUnencrypted\s*[:=]?\s*true') {
            $winrmIssues += 'WinRM allows unencrypted traffic'
        }
        if ($gpresultContent -match 'AllowBasic\s*[:=]\s*1' -or $gpresultContent -match 'Basic authentication\s*[:=]?\s*Enabled') {
            $winrmIssues += 'WinRM allows Basic authentication (credentials sent in cleartext base64)'
        }
    }

    # Check security policy for WinRM settings
    if ($secPolicyContent -match 'AllowAutoConfig\s*=\s*1') {
        if ($secPolicyContent -match 'TrustedHosts\s*=\s*\*') {
            $winrmIssues += 'WinRM TrustedHosts set to wildcard in security policy'
        }
    }

    if ($winrmIssues.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WGP-006' -Severity 'Medium' -Category 'Group Policy' `
            -Title 'Windows Remote Management (WinRM) configuration issues' `
            -Description "WinRM is enabled with potentially insecure settings. Found $($winrmIssues.Count) configuration concern(s) that could facilitate lateral movement or credential exposure." `
            -ArtifactPath 'security/gpresult.txt' `
            -Evidence $winrmIssues `
            -Recommendation 'Restrict WinRM to specific IP ranges, disable Basic authentication, enforce encryption, and limit TrustedHosts to specific management hosts.' `
            -MITRE 'T1021.006' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Insecure WinRM configuration can expose credentials during transit, allow unauthorized remote management, and facilitate lateral movement across the network.'))
    }

    # ----------------------------------------------------------------
    # WGP-007: Group Policy summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()

    if (Test-Path $gpresultPath) {
        # Extract applied GPOs
        $appliedGPOs = @()
        $inAppliedSection = $false
        foreach ($line in (Read-ArtifactContent -Path $gpresultPath)) {
            if ($line -match 'Applied Group Policy Objects') {
                $inAppliedSection = $true
                continue
            }
            if ($inAppliedSection) {
                $trimmed = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
                if ($trimmed -match '^-{2,}' -or $trimmed -match '^\S.*:') {
                    $inAppliedSection = $false
                    continue
                }
                $appliedGPOs += $trimmed
            }
        }
        if ($appliedGPOs.Count -gt 0) {
            $summaryItems += "Applied GPOs: $($appliedGPOs.Count) - $($appliedGPOs -join ', ')"
        }
    }

    if (Test-Path $auditPolicyPath) {
        $summaryItems += "Audit policy file present: audit_policy.txt"
    }
    else {
        $summaryItems += 'Audit policy file NOT found'
    }

    if (Test-Path $secPolicyPath) {
        $summaryItems += "Security policy file present: security_policy.cfg"
    }
    else {
        $summaryItems += 'Security policy file NOT found'
    }

    $summaryItems += "Script Block Logging: $(if ($scriptBlockLoggingEnabled) { 'Enabled' } else { 'Not enabled' })"
    $summaryItems += "Module Logging: $(if ($moduleLoggingEnabled) { 'Enabled' } else { 'Not enabled' })"
    $summaryItems += "Credential Guard: $(if ($credGuardEnabled) { 'Enabled' } else { 'Not enabled' })"
    $summaryItems += "LSA Protection (RunAsPPL): $(if ($lsaProtectionEnabled) { 'Enabled' } else { 'Not enabled' })"

    $findings.Add((New-Finding -Id 'WGP-007' -Severity 'Informational' -Category 'Group Policy' `
        -Title 'Group Policy configuration summary' `
        -Description 'Summary of Group Policy and security audit configuration findings from the collected evidence.' `
        -ArtifactPath 'security/gpresult.txt' `
        -Evidence $summaryItems `
        -Recommendation 'Review the summary and address any gaps in security policy configuration.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of Group Policy security posture.'))

    return $findings.ToArray()
}
