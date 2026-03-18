function Invoke-WinShareAnalyzer {
    <#
    .SYNOPSIS
        Analyzes network shares and permissions for security misconfigurations.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Load share data from available sources
    $shares = @()
    $sharesCsvPath = Join-Path $EvidencePath 'security/shares.csv'
    $sharesTxtPath = Join-Path $EvidencePath 'security/shares.txt'
    $netSharePath = Join-Path $EvidencePath 'collected_commands/net_share.txt'

    # Parse CSV format (Get-SmbShare output)
    if (Test-Path $sharesCsvPath) {
        $csvLines = Read-ArtifactContent -Path $sharesCsvPath
        $csvContent = $csvLines -join "`n"
        try {
            $parsed = $csvContent | ConvertFrom-Csv -ErrorAction Stop
            foreach ($row in $parsed) {
                $shares += [PSCustomObject]@{
                    Name        = $row.Name
                    Path        = $row.Path
                    Description = $row.Description
                    Permissions = if ($row.PSObject.Properties['AccountAccess'] ) { $row.AccountAccess } `
                                  elseif ($row.PSObject.Properties['AccessControlType']) { "$($row.AccountName):$($row.AccessRight):$($row.AccessControlType)" } `
                                  else { '' }
                    Source      = 'shares.csv'
                }
            }
        }
        catch {
            Write-Verbose "WinShareAnalyzer: Failed to parse shares.csv: $_"
        }
    }
    elseif (Test-Path $sharesTxtPath) {
        $txtLines = Read-ArtifactContent -Path $sharesTxtPath
        foreach ($line in $txtLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($trimmed -match '^Name\s' -or $trimmed -match '^-{2,}') { continue }
            if ($trimmed -match '^(\S+)\s+(.+)$') {
                $shares += [PSCustomObject]@{
                    Name        = $Matches[1]
                    Path        = $Matches[2].Trim()
                    Description = ''
                    Permissions = ''
                    Source      = 'shares.txt'
                }
            }
        }
    }

    # Parse net share output
    $netShareData = @()
    if (Test-Path $netSharePath) {
        $netLines = Read-ArtifactContent -Path $netSharePath
        $inShareList = $false
        $currentPermSection = ''
        $currentShareName = ''
        $currentShareResource = ''
        $currentShareRemark = ''
        $currentPermissions = @()

        foreach ($line in $netLines) {
            $trimmed = $line.Trim()

            # Detect the tabular list header
            if ($trimmed -match '^Share name\s+Resource') {
                $inShareList = $true
                continue
            }
            if ($trimmed -match '^-{2,}') {
                continue
            }

            # Detect detailed share output (from net share <name>)
            if ($line -match '^Share name\s+(.+)$') {
                # Save previous share if exists
                if ($currentShareName -ne '') {
                    $netShareData += [PSCustomObject]@{
                        Name        = $currentShareName
                        Path        = $currentShareResource
                        Description = $currentShareRemark
                        Permissions = ($currentPermissions -join '; ')
                        Source      = 'net_share.txt'
                    }
                }
                $currentShareName = $Matches[1].Trim()
                $currentShareResource = ''
                $currentShareRemark = ''
                $currentPermissions = @()
                $currentPermSection = ''
                $inShareList = $false
                continue
            }
            if ($line -match '^Path\s+(.+)$') {
                $currentShareResource = $Matches[1].Trim()
                continue
            }
            if ($line -match '^Remark\s+(.+)$') {
                $currentShareRemark = $Matches[1].Trim()
                continue
            }
            if ($line -match '^Permission\s') {
                $currentPermSection = 'permission'
                if ($line -match '^Permission\s+(.+)$') {
                    $currentPermissions += $Matches[1].Trim()
                }
                continue
            }
            if ($currentPermSection -eq 'permission' -and $trimmed -match ',\s*(FULL|READ|CHANGE)') {
                $currentPermissions += $trimmed
                continue
            }
            if ($trimmed -match '^The command completed') {
                $currentPermSection = ''
                continue
            }

            # Tabular list parsing
            if ($inShareList -and -not [string]::IsNullOrWhiteSpace($trimmed)) {
                if ($trimmed -match '^The command completed') {
                    $inShareList = $false
                    continue
                }
                # Format: ShareName   C:\Path   Remark
                if ($trimmed -match '^(\S+)\s{2,}(\S.*)$') {
                    $shareName = $Matches[1]
                    $rest = $Matches[2].Trim()
                    $sharePath = ''
                    $remark = ''
                    if ($rest -match '^(\S:\\.+?)\s{2,}(.+)$') {
                        $sharePath = $Matches[1].Trim()
                        $remark = $Matches[2].Trim()
                    }
                    elseif ($rest -match '^(\S:\\.*)$') {
                        $sharePath = $Matches[1].Trim()
                    }
                    else {
                        $sharePath = $rest
                    }

                    $netShareData += [PSCustomObject]@{
                        Name        = $shareName
                        Path        = $sharePath
                        Description = $remark
                        Permissions = ''
                        Source      = 'net_share.txt'
                    }
                }
            }
        }
        # Save last detailed share
        if ($currentShareName -ne '') {
            $netShareData += [PSCustomObject]@{
                Name        = $currentShareName
                Path        = $currentShareResource
                Description = $currentShareRemark
                Permissions = ($currentPermissions -join '; ')
                Source      = 'net_share.txt'
            }
        }
    }

    # Merge: prefer CSV/TXT data, supplement with net share data
    $allShares = @()
    $seenNames = @{}
    foreach ($s in $shares) {
        $allShares += $s
        $seenNames[$s.Name] = $true
    }
    foreach ($s in $netShareData) {
        if (-not $seenNames.ContainsKey($s.Name)) {
            $allShares += $s
            $seenNames[$s.Name] = $true
        }
        else {
            # Supplement permissions if missing
            $existing = $allShares | Where-Object { $_.Name -eq $s.Name }
            if ($existing -and [string]::IsNullOrWhiteSpace($existing.Permissions) -and -not [string]::IsNullOrWhiteSpace($s.Permissions)) {
                $existing.Permissions = $s.Permissions
            }
        }
    }

    # ----------------------------------------------------------------
    # WSHARE-001: Default admin shares exposed to non-admin accounts
    # ----------------------------------------------------------------
    $adminShares = @('C$', 'ADMIN$', 'IPC$', 'D$', 'E$')
    $exposedAdminShares = @()

    foreach ($share in $allShares) {
        if ($share.Name -in $adminShares -and -not [string]::IsNullOrWhiteSpace($share.Permissions)) {
            # Check if non-admin accounts have access
            if ($share.Permissions -match 'Everyone|Authenticated Users|Users|Domain Users' -and $share.Permissions -notmatch 'Deny') {
                $exposedAdminShares += "$($share.Name): $($share.Permissions)"
            }
        }
    }

    if ($exposedAdminShares.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSHARE-001' -Severity 'High' -Category 'Network Shares' `
            -Title 'Default admin shares exposed to non-admin accounts' `
            -Description "Found $($exposedAdminShares.Count) default administrative share(s) with permissions granted to non-administrative accounts. Admin shares should only be accessible to administrators." `
            -ArtifactPath 'security/shares.csv' `
            -Evidence @($exposedAdminShares | Select-Object -First 10) `
            -Recommendation 'Remove non-administrative account access from default admin shares (C$, ADMIN$, IPC$). Consider disabling admin shares via registry if not required.' `
            -MITRE 'T1021.002' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Non-admin accounts with access to administrative shares can read/write to system drives and admin directories, enabling data exfiltration, malware deployment, and lateral movement.'))
    }

    # ----------------------------------------------------------------
    # WSHARE-002: Share with Everyone having Full Control
    # ----------------------------------------------------------------
    $everyoneFullControl = @()

    foreach ($share in $allShares) {
        if ([string]::IsNullOrWhiteSpace($share.Permissions)) { continue }
        if ($share.Permissions -match 'Everyone.*(FULL|Full Control)' -and $share.Permissions -notmatch 'Deny') {
            $everyoneFullControl += "$($share.Name) ($($share.Path)): $($share.Permissions)"
        }
    }

    if ($everyoneFullControl.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSHARE-002' -Severity 'High' -Category 'Network Shares' `
            -Title 'Share with Everyone having Full Control' `
            -Description "Found $($everyoneFullControl.Count) share(s) granting Full Control to Everyone. This allows any user or anonymous connection to read, write, and delete files." `
            -ArtifactPath 'security/shares.csv' `
            -Evidence @($everyoneFullControl | Select-Object -First 10) `
            -Recommendation 'Remove the Everyone principal from share permissions and grant access only to specific users or security groups with least-privilege access.' `
            -MITRE 'T1078' `
            -CVSSv3Score '8.8' `
            -TechnicalImpact 'Anyone on the network can read, modify, or delete files on the share, enabling data theft, ransomware deployment, or planting malicious executables.'))
    }

    # ----------------------------------------------------------------
    # WSHARE-003: Non-default shares with wide permissions
    # ----------------------------------------------------------------
    $widePermShares = @()
    $defaultShareNames = @('C$', 'D$', 'E$', 'ADMIN$', 'IPC$', 'print$', 'NETLOGON', 'SYSVOL')

    foreach ($share in $allShares) {
        if ($share.Name -in $defaultShareNames) { continue }
        if ([string]::IsNullOrWhiteSpace($share.Permissions)) { continue }
        if ($share.Permissions -match 'Everyone|Authenticated Users|Domain Users' -and $share.Permissions -match 'FULL|Full Control|CHANGE|Change') {
            if ($share.Permissions -notmatch 'Deny') {
                $widePermShares += "$($share.Name) ($($share.Path)): $($share.Permissions)"
            }
        }
    }

    if ($widePermShares.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSHARE-003' -Severity 'Medium' -Category 'Network Shares' `
            -Title 'Non-default shares with overly broad permissions' `
            -Description "Found $($widePermShares.Count) non-default share(s) granting Change or Full Control to broad groups (Everyone, Authenticated Users, Domain Users)." `
            -ArtifactPath 'security/shares.csv' `
            -Evidence @($widePermShares | Select-Object -First 10) `
            -Recommendation 'Restrict share permissions to specific security groups. Replace broad groups with role-based access and limit to Read-only where write is not required.' `
            -MITRE 'T1078' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Broad write permissions on network shares allow any domain user to modify shared files, enabling malware distribution, data manipulation, or supply-chain attacks via shared scripts.'))
    }

    # ----------------------------------------------------------------
    # WSHARE-004: Share pointing to system directory
    # ----------------------------------------------------------------
    $systemDirShares = @()
    $systemPaths = @('C:\Windows', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData', 'C:\')

    foreach ($share in $allShares) {
        if ($share.Name -in $adminShares) { continue }  # Skip default admin shares
        if ([string]::IsNullOrWhiteSpace($share.Path)) { continue }
        foreach ($sysPath in $systemPaths) {
            if ($share.Path -eq $sysPath -or $share.Path -like "$sysPath\*") {
                $systemDirShares += "$($share.Name) -> $($share.Path)"
                break
            }
        }
    }

    if ($systemDirShares.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSHARE-004' -Severity 'Medium' -Category 'Network Shares' `
            -Title 'Share pointing to system directory' `
            -Description "Found $($systemDirShares.Count) non-default share(s) pointing to system directories. Sharing system directories increases the risk of unauthorized modification of OS files or program binaries." `
            -ArtifactPath 'security/shares.csv' `
            -Evidence @($systemDirShares | Select-Object -First 10) `
            -Recommendation 'Remove shares that expose system directories. If sharing is required, use a dedicated data directory with restricted permissions.' `
            -MITRE 'T1080' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Network-accessible system directories allow remote modification of OS binaries, DLL hijacking, or planting persistence mechanisms in startup locations.'))
    }

    # ----------------------------------------------------------------
    # WSHARE-005: Share summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()
    $summaryItems += "Total shares discovered: $($allShares.Count)"

    $defaultCount = ($allShares | Where-Object { $_.Name -in $defaultShareNames }).Count
    $customCount = $allShares.Count - $defaultCount
    $summaryItems += "Default shares: $defaultCount"
    $summaryItems += "Custom shares: $customCount"

    if (Test-Path $sharesCsvPath) {
        $summaryItems += 'Source: shares.csv (Get-SmbShare export)'
    }
    elseif (Test-Path $sharesTxtPath) {
        $summaryItems += 'Source: shares.txt'
    }
    if (Test-Path $netSharePath) {
        $summaryItems += 'Source: net_share.txt (net share output)'
    }

    foreach ($share in $allShares) {
        $summaryItems += "  $($share.Name) -> $($share.Path)"
    }

    $findings.Add((New-Finding -Id 'WSHARE-005' -Severity 'Informational' -Category 'Network Shares' `
        -Title 'Network share summary' `
        -Description 'Summary of all discovered network shares and their configurations.' `
        -ArtifactPath 'security/shares.csv' `
        -Evidence @($summaryItems | Select-Object -First 20) `
        -Recommendation 'Review all shares and ensure each has a legitimate business purpose with appropriately scoped permissions.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of network share configuration.'))

    return $findings.ToArray()
}
