function Invoke-FstabAnalyzer {
    <#
    .SYNOPSIS
        Analyzes /etc/fstab for mount security options.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $fstabPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/fstab'
    if (-not (Test-Path $fstabPath)) {
        return @()
    }

    $lines = Read-ArtifactContent -Path $fstabPath
    $mountEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

        $parts = $trimmed -split '\s+', 6
        if ($parts.Count -ge 4) {
            $mountEntries.Add([PSCustomObject]@{
                Device     = $parts[0]
                MountPoint = $parts[1]
                FsType     = $parts[2]
                Options    = if ($parts.Count -ge 4) { $parts[3] } else { 'defaults' }
                Dump       = if ($parts.Count -ge 5) { $parts[4] } else { '0' }
                Pass       = if ($parts.Count -ge 6) { $parts[5] } else { '0' }
            })
        }
    }

    # Check /tmp mount options
    $tmpMounts = $mountEntries | Where-Object { $_.MountPoint -in @('/tmp', '/var/tmp', '/dev/shm') }
    foreach ($mount in $tmpMounts) {
        $options = $mount.Options.Split(',')
        $mp = $mount.MountPoint

        if ('noexec' -notin $options) {
            $findings.Add((New-Finding -Id "FSTAB-001" -Severity "Medium" -Category "Filesystem Security" `
                -Title "Missing noexec on $mp" `
                -Description "$mp is mounted without the noexec option, allowing execution of binaries from this temporary directory." `
                -ArtifactPath "/etc/fstab" `
                -Evidence @("$($mount.Device) $mp $($mount.FsType) $($mount.Options)") `
                -Recommendation "Add noexec option to $mp mount in /etc/fstab" `
                -MITRE "T1059"))
        }
        if ('nosuid' -notin $options) {
            $findings.Add((New-Finding -Id "FSTAB-002" -Severity "Medium" -Category "Filesystem Security" `
                -Title "Missing nosuid on $mp" `
                -Description "$mp is mounted without the nosuid option, allowing SUID binaries to execute from this directory." `
                -ArtifactPath "/etc/fstab" `
                -Evidence @("$($mount.Device) $mp $($mount.FsType) $($mount.Options)") `
                -Recommendation "Add nosuid option to $mp mount in /etc/fstab" `
                -MITRE "T1548.001"))
        }
        if ('nodev' -notin $options) {
            $findings.Add((New-Finding -Id "FSTAB-003" -Severity "Low" -Category "Filesystem Security" `
                -Title "Missing nodev on $mp" `
                -Description "$mp is mounted without the nodev option." `
                -ArtifactPath "/etc/fstab" `
                -Evidence @("$($mount.Device) $mp $($mount.FsType) $($mount.Options)") `
                -Recommendation "Add nodev option to $mp mount in /etc/fstab" `
                -MITRE "T1068"))
        }
    }

    # Check if /tmp is a separate partition at all
    $tmpPartition = $mountEntries | Where-Object { $_.MountPoint -eq '/tmp' }
    if (-not $tmpPartition) {
        $findings.Add((New-Finding -Id "FSTAB-004" -Severity "Medium" -Category "Filesystem Security" `
            -Title "/tmp is not a separate partition" `
            -Description "/tmp does not have its own mount entry in /etc/fstab. It is likely part of the root filesystem, preventing mount-level security controls." `
            -ArtifactPath "/etc/fstab" `
            -Evidence @("No /tmp entry found in fstab") `
            -Recommendation "Create a separate partition or tmpfs mount for /tmp with noexec,nosuid,nodev options" `
            -MITRE "T1059"))
    }

    # Check /home mount options
    $homeMounts = $mountEntries | Where-Object { $_.MountPoint -eq '/home' }
    foreach ($mount in $homeMounts) {
        $options = $mount.Options.Split(',')
        if ('nosuid' -notin $options) {
            $findings.Add((New-Finding -Id "FSTAB-005" -Severity "Low" -Category "Filesystem Security" `
                -Title "Missing nosuid on /home" `
                -Description "/home is mounted without nosuid, allowing SUID binaries in user home directories." `
                -ArtifactPath "/etc/fstab" `
                -Evidence @("$($mount.Device) /home $($mount.FsType) $($mount.Options)") `
                -Recommendation "Add nosuid option to /home mount" `
                -MITRE "T1548.001"))
        }
    }

    # Summary
    $findings.Add((New-Finding -Id "FSTAB-INFO" -Severity "Informational" -Category "Filesystem Security" `
        -Title "Fstab configuration summary" `
        -Description "Found $($mountEntries.Count) mount entries in /etc/fstab." `
        -ArtifactPath "/etc/fstab" `
        -Evidence @($mountEntries | ForEach-Object { "$($_.MountPoint) ($($_.FsType)) opts=$($_.Options)" }) `
        -Recommendation "Review mount options against CIS benchmarks"))

    return $findings.ToArray()
}
