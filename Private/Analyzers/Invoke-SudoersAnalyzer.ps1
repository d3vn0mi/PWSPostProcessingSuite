function Invoke-SudoersAnalyzer {
    <#
    .SYNOPSIS
        Analyzes sudoers configuration for privilege escalation risks.
    .DESCRIPTION
        Examines /etc/sudoers and /etc/sudoers.d/* for dangerous rules including
        NOPASSWD ALL, ALL command grants, dangerous binary access, and insecure
        defaults directives.
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
    $analyzerCategory = 'Sudoers Configuration'
    $mitreSudo = 'T1548.003'

    # ----------------------------------------------------------------
    # Collect all sudoers content from main file and sudoers.d/
    # ----------------------------------------------------------------
    $sudoersFiles = [System.Collections.Generic.List[hashtable]]::new()

    # Main sudoers file
    $mainSudoersPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'etc/sudoers'
    if (Test-Path $mainSudoersPath -PathType Leaf) {
        $sudoersFiles.Add(@{
            Path      = $mainSudoersPath
            LinuxPath = '/etc/sudoers'
            Lines     = @(Read-ArtifactContent -Path $mainSudoersPath)
        })
    }

    # sudoers.d/ drop-in files
    $sudoersDFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath 'etc/sudoers.d'
    foreach ($file in $sudoersDFiles) {
        $sudoersFiles.Add(@{
            Path      = $file.FullName
            LinuxPath = "/etc/sudoers.d/$($file.Name)"
            Lines     = @(Read-ArtifactContent -Path $file.FullName)
        })
    }

    if ($sudoersFiles.Count -eq 0) {
        Write-Verbose "SudoersAnalyzer: No sudoers files found, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Build dangerous binaries lookup from rules
    # ----------------------------------------------------------------
    $dangerousBinaries = @()
    if ($Rules.ContainsKey('dangerous_sudoers_binaries') -and $null -ne $Rules['dangerous_sudoers_binaries']) {
        $dangerousBinaries = @($Rules['dangerous_sudoers_binaries'])
    }

    # Also build a set of just the binary names for matching (e.g. "vim" from "/usr/bin/vim")
    $dangerousBinaryNames = @{}
    foreach ($bin in $dangerousBinaries) {
        $name = Split-Path $bin -Leaf
        $dangerousBinaryNames[$name] = $bin
        # Store full path too for direct matching
        $dangerousBinaryNames[$bin] = $bin
    }

    # ----------------------------------------------------------------
    # Tracking for summary
    # ----------------------------------------------------------------
    $totalRules = 0
    $includedFiles = [System.Collections.Generic.List[string]]::new()
    $allEffectiveLines = [System.Collections.Generic.List[string]]::new()
    $script:hasUsePty = $false
    $script:hasSudoLogfile = $false

    # ----------------------------------------------------------------
    # Process each sudoers file
    # ----------------------------------------------------------------
    foreach ($sudoersFile in $sudoersFiles) {
        $filePath = $sudoersFile.Path
        $linuxPath = $sudoersFile.LinuxPath
        $lines = $sudoersFile.Lines

        foreach ($rawLine in $lines) {
            $line = $rawLine.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                # Check for #include and #includedir directives (these start with # but are not comments)
                if ($line -match '^#include\s+(.+)$') {
                    $includedFiles.Add($Matches[1])
                }
                elseif ($line -match '^#includedir\s+(.+)$') {
                    $includedFiles.Add("$($Matches[1])/*")
                }
                # Also handle @include / @includedir (newer sudoers syntax)
                continue
            }

            # Handle @include/@includedir (modern sudoers)
            if ($line -match '^@include\s+(.+)$') {
                $includedFiles.Add($Matches[1])
                continue
            }
            if ($line -match '^@includedir\s+(.+)$') {
                $includedFiles.Add("$($Matches[1])/*")
                continue
            }

            $totalRules++
            $allEffectiveLines.Add("[$linuxPath] $line")

            # ----------------------------------------------------------------
            # SUDO-001: NOPASSWD: ALL rules
            # Severity depends on the principal:
            #   - root: Informational (root already has unrestricted access;
            #     NOPASSWD is redundant per CIS Benchmark 5.3.5 context)
            #   - %sudo / %wheel / %admin groups: High (these are standard
            #     privileged groups but NOPASSWD weakens credential verification
            #     per CIS Benchmark 5.3.5: "Ensure sudo commands use pty")
            #   - Any other user/group: Critical (violates CIS 5.3.4:
            #     "Ensure users must provide password for privilege escalation")
            # ----------------------------------------------------------------
            if ($line -match 'NOPASSWD\s*:\s*ALL') {
                # Extract the principal (user or %group) from the rule
                $principal = ''
                if ($line -match '^\s*(%?\S+)\s+') {
                    $principal = $Matches[1]
                }

                if ($principal -eq 'root') {
                    # root already has UID 0 with full system access. NOPASSWD
                    # for root is redundant and carries no additional risk.
                    $findings.Add((New-Finding `
                        -Id 'SUDO-001' `
                        -Severity 'Informational' `
                        -Category $analyzerCategory `
                        -Title "NOPASSWD ALL for root in $linuxPath (redundant)" `
                        -Description "The root user is granted NOPASSWD: ALL in sudoers. Since root (UID 0) already has unrestricted system access, this directive is redundant and does not introduce additional risk. This is a default configuration on many distributions." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation 'No action required. This rule is functionally redundant since root already has full system access. You may remove it for configuration cleanliness.' `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '' `
                        -TechnicalImpact 'None. Root already has unrestricted access; NOPASSWD does not grant additional privileges.'
                    ))
                }
                elseif ($principal -match '^%(sudo|wheel|admin)$') {
                    # Standard privileged groups with NOPASSWD weakens the
                    # authentication barrier. CIS Benchmark 5.3.4 recommends
                    # requiring password for escalation.
                    $findings.Add((New-Finding `
                        -Id 'SUDO-001' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "NOPASSWD ALL for privileged group '$principal' in $linuxPath" `
                        -Description "The privileged group '$principal' is granted NOPASSWD: ALL. While members of this group are expected to have sudo access, removing the password requirement weakens authentication controls. Per CIS Benchmark 5.3.4, users should provide a password for privilege escalation to ensure accountability and prevent abuse from unattended sessions or stolen SSH keys." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation "Remove the NOPASSWD directive so group '$principal' members must authenticate: $($principal) ALL=(ALL:ALL) ALL. If passwordless sudo is needed for automation, restrict it to specific commands." `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '7.2' `
                        -TechnicalImpact "Any member of the '$principal' group can escalate to root without a password. Compromised SSH keys or unattended terminals grant immediate root access without an additional authentication barrier."
                    ))
                }
                else {
                    # Non-root, non-standard-group principal with NOPASSWD: ALL
                    # is the most dangerous scenario - Critical severity.
                    $findings.Add((New-Finding `
                        -Id 'SUDO-001' `
                        -Severity 'Critical' `
                        -Category $analyzerCategory `
                        -Title "NOPASSWD ALL rule for '$principal' in $linuxPath" `
                        -Description "User or group '$principal' is granted NOPASSWD: ALL, allowing full privilege escalation to root without any password verification. This violates CIS Benchmark 5.3.4 ('Ensure users must provide password for privilege escalation') and represents a critical security gap. Any compromise of this account (e.g., via SSH key theft, web application exploit, or lateral movement) immediately yields full root access." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation "Remove the NOPASSWD: ALL directive for '$principal'. If passwordless sudo is operationally required, restrict it to specific safe commands only (e.g., $principal ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myservice)." `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '9.8' `
                        -TechnicalImpact "Enables full privilege escalation from '$principal' to root without password authentication. Any compromise of this account immediately yields unrestricted root access."
                    ))
                }
            }

            # ----------------------------------------------------------------
            # SUDO-002: Rules granting ALL command access (without NOPASSWD: ALL)
            # Severity depends on the principal:
            #   - root: Informational (expected default, CIS does not flag this)
            #   - %sudo/%wheel/%admin: Low (standard configuration on most distros;
            #     CIS 5.3.4 considers this acceptable when password is required)
            #   - Other users/groups: High (violates principle of least privilege;
            #     CIS 5.3.5 recommends restricting sudo to specific commands)
            # ----------------------------------------------------------------
            if ($line -notmatch 'NOPASSWD\s*:\s*ALL' -and $line -match '=\s*\(.*\)\s*ALL' -and $line -notmatch '^Defaults') {
                $sudo002Principal = ''
                if ($line -match '^\s*(%?\S+)\s+') {
                    $sudo002Principal = $Matches[1]
                }

                if ($sudo002Principal -eq 'root') {
                    # root ALL=(ALL:ALL) ALL is the standard default sudoers entry.
                    # It simply allows root to run commands as any user, which root
                    # can already do natively. CIS does not flag this.
                    $findings.Add((New-Finding `
                        -Id 'SUDO-002' `
                        -Severity 'Informational' `
                        -Category $analyzerCategory `
                        -Title "Standard root ALL rule in $linuxPath" `
                        -Description "The default 'root ALL=(ALL:ALL) ALL' entry was found. This is the standard sudoers configuration shipped by all major distributions and does not introduce additional risk since root already has UID 0 with unrestricted access." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation 'No action required. This is a standard default configuration.' `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '' `
                        -TechnicalImpact 'None. Root already has unrestricted system access.'
                    ))
                }
                elseif ($sudo002Principal -match '^%(sudo|wheel|admin)$') {
                    # Standard privileged groups with ALL command access and password
                    # required is the expected configuration per CIS Benchmark 5.3.4.
                    $findings.Add((New-Finding `
                        -Id 'SUDO-002' `
                        -Severity 'Low' `
                        -Category $analyzerCategory `
                        -Title "Standard ALL command access for group '$sudo002Principal' in $linuxPath" `
                        -Description "Group '$sudo002Principal' has ALL command access with password required. This is the standard sudo configuration on most Linux distributions. Per CIS Benchmark 5.3.4, this is acceptable when password authentication is enforced. However, the principle of least privilege recommends restricting commands where feasible." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation "This is a standard configuration. For enhanced security, consider restricting to specific commands if the group's responsibilities are well-defined." `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '4.0' `
                        -TechnicalImpact "Members of '$sudo002Principal' can escalate to root with password authentication. This is expected behavior for administrative groups."
                    ))
                }
                else {
                    # Non-standard user/group with ALL command access
                    $findings.Add((New-Finding `
                        -Id 'SUDO-002' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "ALL command access for '$sudo002Principal' in $linuxPath" `
                        -Description "User or group '$sudo002Principal' has ALL command access via sudo. Per CIS Benchmark 5.3.5, sudo rules should be restricted to the minimum set of commands required. Granting ALL commands to non-standard accounts violates the principle of least privilege and increases the blast radius if this account is compromised." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation "Restrict sudo access for '$sudo002Principal' to specific required commands instead of ALL. Example: $sudo002Principal ALL=(ALL) /usr/bin/systemctl, /usr/bin/journalctl" `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '8.2' `
                        -TechnicalImpact "Enables full privilege escalation to root for '$sudo002Principal'. If this account is compromised, the attacker gains complete administrative control."
                    ))
                }
            }

            # ----------------------------------------------------------------
            # SUDO-003 (High): Dangerous binaries in sudoers
            # Check if the line references any known dangerous binaries
            # ----------------------------------------------------------------
            if ($dangerousBinaries.Count -gt 0 -and $line -notmatch '^Defaults') {
                $matchedBinaries = [System.Collections.Generic.List[string]]::new()
                foreach ($bin in $dangerousBinaries) {
                    # Match full path or just the binary name in the command portion
                    $escapedBin = [regex]::Escape($bin)
                    $binName = Split-Path $bin -Leaf
                    $escapedName = [regex]::Escape($binName)

                    if ($line -match $escapedBin -or $line -match "(?<=[=/\s])$escapedName(?:\s|,|$)") {
                        $matchedBinaries.Add($bin)
                    }
                }

                foreach ($matchedBin in $matchedBinaries) {
                    $binName = Split-Path $matchedBin -Leaf
                    # Classify the risk level based on the binary type
                    $binRiskDetail = switch -Wildcard ($binName) {
                        { $_ -in @('bash','sh','zsh','dash') } { "This is a shell binary that directly provides an interactive root session when run via sudo." }
                        { $_ -in @('python','python3','perl','ruby','lua') } { "This interpreter can execute arbitrary code as root. For example: sudo $binName -c 'import os; os.system(""/bin/sh"")'" }
                        { $_ -in @('vim','vi','nano','less','more','man') } { "This program supports shell escape (e.g., :!sh in vim) that drops to a root shell. See GTFOBins for exploitation details." }
                        { $_ -in @('docker') } { "Docker access is equivalent to root. A user can mount the host filesystem in a privileged container to gain full access." }
                        { $_ -in @('find') } { "find supports -exec which can be used to run arbitrary commands as root: sudo find / -exec /bin/sh \\;" }
                        { $_ -in @('env') } { "env can be used to spawn a root shell: sudo env /bin/sh" }
                        { $_ -in @('nmap') } { "nmap interactive mode (--interactive) or --script can execute arbitrary OS commands as root." }
                        default { "This binary is listed in GTFOBins (https://gtfobins.github.io/) as exploitable for privilege escalation when available via sudo." }
                    }

                    $findings.Add((New-Finding `
                        -Id 'SUDO-003' `
                        -Severity 'High' `
                        -Category $analyzerCategory `
                        -Title "Dangerous binary in sudoers: $matchedBin" `
                        -Description "Sudoers rule in $linuxPath grants access to '$matchedBin'. $binRiskDetail Per CIS Benchmark 5.3.5, sudo should be limited to commands that cannot be used to spawn secondary shells or execute arbitrary code." `
                        -ArtifactPath $filePath `
                        -Evidence @($line) `
                        -Recommendation "Remove sudo access to $matchedBin or replace with a safer alternative. Use 'sudoedit' instead of text editors, dedicated service management commands instead of shells, and restrict interpreters to specific scripts with full paths." `
                        -MITRE $mitreSudo `
                        -CVSSv3Score '7.8' `
                        -TechnicalImpact "Allows privilege escalation to root via GTFOBins exploitation of '$matchedBin'. The attacker can escape to an interactive root shell or read/write arbitrary files on the system."
                    ))
                }
            }

            # ----------------------------------------------------------------
            # SUDO-004: Insecure Defaults directives
            # CIS Benchmark 5.3.3: "Ensure sudo log file exists"
            # CIS Benchmark 5.3.5: "Ensure sudo commands use pty"
            # ----------------------------------------------------------------
            if ($line -match 'Defaults.*!authenticate') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-004' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "Authentication disabled via Defaults in $linuxPath" `
                    -Description "The '!authenticate' directive disables password prompts for sudo globally or for matched users. This is functionally equivalent to NOPASSWD for all commands and violates CIS Benchmark 5.3.4 ('Ensure users must provide password for privilege escalation'). Unlike per-rule NOPASSWD, this Defaults override affects all sudo rules and is easily overlooked in audits." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation 'Remove the !authenticate Defaults directive. If specific commands require passwordless execution, use targeted NOPASSWD rules for those commands only.' `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '7.2' `
                    -TechnicalImpact 'Globally disables password authentication for sudo, allowing any user with sudo access to escalate to root without credential verification.'
                ))
            }

            if ($line -match 'Defaults.*!requiretty') {
                $findings.Add((New-Finding `
                    -Id 'SUDO-004' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "TTY requirement disabled via Defaults in $linuxPath" `
                    -Description "The '!requiretty' directive allows sudo to run without an allocated TTY. Per CIS Benchmark 5.3.5 ('Ensure sudo commands use pty'), sudo should require a pseudo-TTY to prevent session hijacking and ensure proper logging. Without this, attackers can escalate privileges from non-interactive contexts such as cron jobs, web shells, or compromised services." `
                    -ArtifactPath $filePath `
                    -Evidence @($line) `
                    -Recommendation "Remove '!requiretty' and add 'Defaults use_pty' per CIS Benchmark 5.3.5. If automation requires non-TTY sudo, restrict those rules to specific commands and users." `
                    -MITRE $mitreSudo `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Allows sudo execution without a TTY, enabling privilege escalation from non-interactive sessions (web shells, cron, compromised daemons) and reducing audit trail fidelity.'
                ))
            }

            # SUDO-004 additional: Check for missing use_pty (CIS 5.3.5)
            if ($line -match '^Defaults\s+use_pty') {
                # Good - use_pty is enabled, track this for summary
                $script:hasUsePty = $true
            }

            # SUDO-004 additional: Check for sudo logging (CIS 5.3.3)
            if ($line -match 'Defaults\s+logfile\s*=') {
                $script:hasSudoLogfile = $true
            }
        }
    }

    # ----------------------------------------------------------------
    # SUDO-006 (Medium): Missing 'Defaults use_pty' (CIS 5.3.5)
    # ----------------------------------------------------------------
    if (-not $script:hasUsePty) {
        $findings.Add((New-Finding `
            -Id 'SUDO-006' `
            -Severity 'Medium' `
            -Category $analyzerCategory `
            -Title "Missing 'Defaults use_pty' directive (CIS 5.3.5)" `
            -Description "No 'Defaults use_pty' directive was found in any sudoers file. CIS Benchmark 5.3.5 requires that sudo allocates a pseudo-TTY for commands. Without use_pty, attackers can exploit background processes and inject commands into the parent session." `
            -ArtifactPath ($sudoersFiles[0].Path) `
            -Evidence @('No Defaults use_pty directive found in any analyzed sudoers file') `
            -Recommendation "Add 'Defaults use_pty' to /etc/sudoers or a file in /etc/sudoers.d/ per CIS Benchmark 5.3.5." `
            -MITRE $mitreSudo `
            -CVSSv3Score '4.3' `
            -TechnicalImpact 'Without pseudo-TTY allocation, sudo commands can be exploited for session hijacking and reduce the effectiveness of audit logging.'
        ))
    }

    # ----------------------------------------------------------------
    # SUDO-007 (Low): Missing sudo logfile (CIS 5.3.3)
    # ----------------------------------------------------------------
    if (-not $script:hasSudoLogfile) {
        $findings.Add((New-Finding `
            -Id 'SUDO-007' `
            -Severity 'Low' `
            -Category $analyzerCategory `
            -Title "Missing 'Defaults logfile' directive (CIS 5.3.3)" `
            -Description "No 'Defaults logfile' directive was found. CIS Benchmark 5.3.3 recommends configuring a dedicated sudo log file for accountability and forensic analysis. Without this, sudo events are only logged via syslog which may be harder to monitor and could be tampered with." `
            -ArtifactPath ($sudoersFiles[0].Path) `
            -Evidence @('No Defaults logfile directive found in any analyzed sudoers file') `
            -Recommendation "Add 'Defaults logfile=\"/var/log/sudo.log\"' to /etc/sudoers per CIS Benchmark 5.3.3." `
            -MITRE $mitreSudo `
            -CVSSv3Score '2.6' `
            -TechnicalImpact 'Without a dedicated sudo logfile, forensic analysis of privilege escalation events is more difficult and relies solely on syslog.'
        ))
    }

    # ----------------------------------------------------------------
    # SUDO-005 (Informational): Full sudoers summary
    # ----------------------------------------------------------------
    $summaryEvidence = [System.Collections.Generic.List[string]]::new()
    $summaryEvidence.Add("Sudoers files analyzed: $($sudoersFiles.Count)")
    foreach ($sf in $sudoersFiles) {
        $summaryEvidence.Add("  - $($sf.LinuxPath) ($($sf.Lines.Count) lines)")
    }
    $summaryEvidence.Add("Total effective rules: $totalRules")
    if ($includedFiles.Count -gt 0) {
        $summaryEvidence.Add("Include directives found:")
        foreach ($inc in $includedFiles) {
            $summaryEvidence.Add("  - $inc")
        }
    }

    $findings.Add((New-Finding `
        -Id 'SUDO-005' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Sudoers configuration summary' `
        -Description 'Summary of sudoers configuration files analyzed and effective rules found.' `
        -ArtifactPath ($sudoersFiles[0].Path) `
        -Evidence @($summaryEvidence) `
        -MITRE $mitreSudo `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
