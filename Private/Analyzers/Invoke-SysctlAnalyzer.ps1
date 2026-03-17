function Invoke-SysctlAnalyzer {
    <#
    .SYNOPSIS
        Analyzes sysctl kernel parameters for security misconfigurations.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect sysctl config from multiple sources
    $sysctlFiles = @()
    $mainConf = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/sysctl.conf'
    if (Test-Path $mainConf) { $sysctlFiles += $mainConf }

    $sysctlD = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc/sysctl.d' -Filter '*.conf'
    foreach ($f in $sysctlD) { $sysctlFiles += $f.FullName }

    # Also check for sysctl output dump
    $sysctlDump = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc/sys'
    # Some collections include sysctl -a output
    $sysctlOutput = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter 'sysctl*'
    foreach ($f in $sysctlOutput) {
        if ($f.Name -match 'sysctl' -and $f.Length -gt 0) { $sysctlFiles += $f.FullName }
    }

    if ($sysctlFiles.Count -eq 0) {
        return @()
    }

    # Parse all sysctl settings into a hashtable
    $settings = @{}
    foreach ($file in $sysctlFiles) {
        $lines = Read-ArtifactContent -Path $file
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#') -or $trimmed.StartsWith(';')) { continue }

            if ($trimmed -match '^\s*([^=]+?)\s*=\s*(.+)$') {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                $settings[$key] = @{ Value = $value; Source = $file }
            }
        }
    }

    # Check against rules
    $checkId = 0
    $checks = @(
        @{ Key = 'net.ipv4.ip_forward'; BadValues = @('1'); Severity = 'Medium'; Title = 'IP forwarding enabled'; MITRE = 'T1090'; Recommendation = 'Disable unless this system is a router: net.ipv4.ip_forward = 0' }
        @{ Key = 'kernel.randomize_va_space'; BadValues = @('0'); Severity = 'High'; Title = 'ASLR disabled'; MITRE = 'T1211'; Recommendation = 'Enable ASLR: kernel.randomize_va_space = 2' }
        @{ Key = 'net.ipv4.conf.all.accept_redirects'; BadValues = @('1'); Severity = 'Medium'; Title = 'ICMP redirects accepted'; MITRE = 'T1557'; Recommendation = 'Disable: net.ipv4.conf.all.accept_redirects = 0' }
        @{ Key = 'net.ipv4.conf.all.send_redirects'; BadValues = @('1'); Severity = 'Medium'; Title = 'ICMP redirect sending enabled'; MITRE = 'T1557'; Recommendation = 'Disable: net.ipv4.conf.all.send_redirects = 0' }
        @{ Key = 'net.ipv4.tcp_syncookies'; BadValues = @('0'); Severity = 'Medium'; Title = 'SYN cookies disabled'; MITRE = 'T1499'; Recommendation = 'Enable: net.ipv4.tcp_syncookies = 1' }
        @{ Key = 'fs.protected_hardlinks'; BadValues = @('0'); Severity = 'Medium'; Title = 'Hardlink protection disabled'; MITRE = 'T1068'; Recommendation = 'Enable: fs.protected_hardlinks = 1' }
        @{ Key = 'fs.protected_symlinks'; BadValues = @('0'); Severity = 'Medium'; Title = 'Symlink protection disabled'; MITRE = 'T1068'; Recommendation = 'Enable: fs.protected_symlinks = 1' }
        @{ Key = 'fs.suid_dumpable'; BadValues = @('1', '2'); Severity = 'Medium'; Title = 'SUID core dumps enabled'; MITRE = 'T1003'; Recommendation = 'Disable: fs.suid_dumpable = 0' }
        @{ Key = 'net.ipv4.conf.all.accept_source_route'; BadValues = @('1'); Severity = 'Medium'; Title = 'Source routing accepted'; MITRE = 'T1557'; Recommendation = 'Disable: net.ipv4.conf.all.accept_source_route = 0' }
        @{ Key = 'net.ipv4.conf.all.log_martians'; BadValues = @('0'); Severity = 'Low'; Title = 'Martian packet logging disabled'; MITRE = 'T1562'; Recommendation = 'Enable: net.ipv4.conf.all.log_martians = 1' }
        @{ Key = 'net.ipv6.conf.all.accept_redirects'; BadValues = @('1'); Severity = 'Medium'; Title = 'IPv6 ICMP redirects accepted'; MITRE = 'T1557'; Recommendation = 'Disable: net.ipv6.conf.all.accept_redirects = 0' }
        @{ Key = 'net.ipv4.icmp_echo_ignore_broadcasts'; BadValues = @('0'); Severity = 'Low'; Title = 'ICMP broadcast responses enabled (smurf attack vector)'; MITRE = 'T1498'; Recommendation = 'Enable: net.ipv4.icmp_echo_ignore_broadcasts = 1' }
    )

    foreach ($check in $checks) {
        $checkId++
        if ($settings.ContainsKey($check.Key)) {
            $currentValue = $settings[$check.Key].Value
            $source = $settings[$check.Key].Source
            if ($currentValue -in $check.BadValues) {
                $cvss = switch ($check.Severity) {
                    'Critical' { '9.8' }
                    'High'     { '7.5' }
                    'Medium'   { '5.3' }
                    'Low'      { '3.1' }
                    default    { '' }
                }
                $impact = "Insecure kernel parameter $($check.Key) = $currentValue may weaken system defenses or enable network-based attacks."
                $findings.Add((New-Finding -Id "SYSCTL-$('{0:D3}' -f $checkId)" -Severity $check.Severity -Category "Kernel Security" `
                    -Title $check.Title `
                    -Description "Kernel parameter $($check.Key) is set to '$currentValue' which is a security concern." `
                    -ArtifactPath $source `
                    -Evidence @("$($check.Key) = $currentValue") `
                    -Recommendation $check.Recommendation `
                    -MITRE $check.MITRE `
                    -CVSSv3Score $cvss `
                    -TechnicalImpact $impact))
            }
        }
    }

    # Special check: kernel.core_pattern piping to commands
    if ($settings.ContainsKey('kernel.core_pattern')) {
        $val = $settings['kernel.core_pattern'].Value
        if ($val.StartsWith('|')) {
            $findings.Add((New-Finding -Id "SYSCTL-CORE" -Severity "High" -Category "Kernel Security" `
                -Title "Core dump pattern pipes to external command" `
                -Description "kernel.core_pattern starts with '|' which pipes core dumps to a command. This can be used for privilege escalation." `
                -ArtifactPath $settings['kernel.core_pattern'].Source `
                -Evidence @("kernel.core_pattern = $val") `
                -Recommendation "Review the command that receives core dumps. Ensure it is a legitimate core dump handler." `
                -MITRE "T1068" `
                -CVSSv3Score '7.8' `
                -TechnicalImpact 'Core dump piping to an external command can be exploited for privilege escalation by crafting core dumps that trigger arbitrary code execution as root.'))
        }
    }

    # Summary
    $findings.Add((New-Finding -Id "SYSCTL-INFO" -Severity "Informational" -Category "Kernel Security" `
        -Title "Sysctl configuration summary" `
        -Description "Analyzed $($settings.Count) kernel parameters from $($sysctlFiles.Count) config files." `
        -ArtifactPath "/etc/sysctl.conf" `
        -Evidence @("Total parameters: $($settings.Count)", "Config files: $($sysctlFiles.Count)") `
        -Recommendation "Review all kernel parameters against CIS benchmarks" `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    return $findings.ToArray()
}
