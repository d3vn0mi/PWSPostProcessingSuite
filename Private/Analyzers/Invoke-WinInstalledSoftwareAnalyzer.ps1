function Invoke-WinInstalledSoftwareAnalyzer {
    <#
    .SYNOPSIS
        Analyzes installed software and patches for security issues.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ----------------------------------------------------------------
    # Collect installed software from multiple sources
    # ----------------------------------------------------------------
    $softwareItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Try CSV first
    $softwareCsvPath = Join-Path $EvidencePath 'software/installed_software.csv'
    if (Test-Path $softwareCsvPath) {
        try {
            $csvItems = Import-Csv -Path $softwareCsvPath -ErrorAction Stop
            foreach ($item in $csvItems) {
                $name = ''
                $version = ''
                $publisher = ''
                $installDate = ''

                if ($item.PSObject.Properties['DisplayName']) { $name = $item.DisplayName }
                elseif ($item.PSObject.Properties['Name']) { $name = $item.Name }
                elseif ($item.PSObject.Properties['Software']) { $name = $item.Software }

                if ($item.PSObject.Properties['DisplayVersion']) { $version = $item.DisplayVersion }
                elseif ($item.PSObject.Properties['Version']) { $version = $item.Version }

                if ($item.PSObject.Properties['Publisher']) { $publisher = $item.Publisher }
                elseif ($item.PSObject.Properties['Vendor']) { $publisher = $item.Vendor }

                if ($item.PSObject.Properties['InstallDate']) { $installDate = $item.InstallDate }

                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $softwareItems.Add([PSCustomObject]@{
                        Name        = $name.Trim()
                        Version     = $version.Trim()
                        Publisher   = $publisher.Trim()
                        InstallDate = $installDate.Trim()
                        Source      = 'installed_software.csv'
                    })
                }
            }
        }
        catch {
            Write-Verbose "Failed to parse installed_software.csv: $_"
        }
    }

    # Try plain text file
    $softwareTxtPath = Join-Path $EvidencePath 'software/installed_software.txt'
    if (Test-Path $softwareTxtPath) {
        $softwareLines = Read-ArtifactContent -Path $softwareTxtPath
        foreach ($line in $softwareLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed -match '^(---|----|Name|DisplayName|=)') { continue }

            $softwareItems.Add([PSCustomObject]@{
                Name        = $trimmed
                Version     = ''
                Publisher   = ''
                InstallDate = ''
                Source      = 'installed_software.txt'
            })
        }
    }

    # Try installed_programs.txt (from registry uninstall keys)
    $installedProgramsPath = Join-Path $EvidencePath 'software/installed_programs.txt'
    if (Test-Path $installedProgramsPath) {
        $programLines = Read-ArtifactContent -Path $installedProgramsPath
        foreach ($line in $programLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed -match '^(---|----|Name|DisplayName|=)') { continue }

            # Try to parse "Name  Version" format
            $name = $trimmed
            $version = ''
            if ($trimmed -match '^(.+?)\s{2,}(\d+[\d.]+.*)$') {
                $name = $Matches[1].Trim()
                $version = $Matches[2].Trim()
            }

            # Avoid duplicates
            $existing = $softwareItems | Where-Object { $_.Name -eq $name }
            if (-not $existing) {
                $softwareItems.Add([PSCustomObject]@{
                    Name        = $name
                    Version     = $version
                    Publisher   = ''
                    InstallDate = ''
                    Source      = 'installed_programs.txt'
                })
            }
        }
    }

    # ----------------------------------------------------------------
    # WSOFT-001: Remote access tools installed
    # ----------------------------------------------------------------
    $remoteAccessPatterns = @(
        '(?i)TeamViewer', '(?i)AnyDesk', '(?i)VNC', '(?i)TightVNC', '(?i)RealVNC', '(?i)UltraVNC',
        '(?i)LogMeIn', '(?i)ScreenConnect', '(?i)ConnectWise',
        '(?i)Splashtop', '(?i)Ammyy', '(?i)RemotePC', '(?i)Radmin',
        '(?i)RustDesk', '(?i)DWService', '(?i)Action1',
        '(?i)GoTo(Assist|MyPC|Meeting)', '(?i)Bomgar', '(?i)BeyondTrust',
        '(?i)SimpleHelp', '(?i)NetSupport', '(?i)Dameware'
    )

    $remoteAccessFound = @()
    foreach ($sw in $softwareItems) {
        foreach ($pattern in $remoteAccessPatterns) {
            if ($sw.Name -match $pattern) {
                $entry = $sw.Name
                if (-not [string]::IsNullOrWhiteSpace($sw.Version)) { $entry += " v$($sw.Version)" }
                if (-not [string]::IsNullOrWhiteSpace($sw.Publisher)) { $entry += " ($($sw.Publisher))" }
                $remoteAccessFound += $entry
                break
            }
        }
    }

    if ($remoteAccessFound.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSOFT-001' -Severity 'High' -Category 'Software' `
            -Title "Remote access tools installed ($($remoteAccessFound.Count) found)" `
            -Description "Found $($remoteAccessFound.Count) remote access tool(s) installed. Remote access tools are commonly abused by attackers for persistent remote control." `
            -ArtifactPath 'software/installed_software.csv' `
            -Evidence @($remoteAccessFound | Select-Object -First 15) `
            -Recommendation 'Verify all remote access tools are authorized. Remove unauthorized tools immediately. Remote access software is frequently used in ransomware and data theft attacks.' `
            -MITRE 'T1219' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Remote access tools provide full remote control of the system, enabling data exfiltration, lateral movement, and persistent access.'))
    }

    # ----------------------------------------------------------------
    # WSOFT-002: Development/hacking tools
    # ----------------------------------------------------------------
    $devToolPatterns = @(
        '(?i)^Python\s', '(?i)Python\s+\d',
        '(?i)Nmap', '(?i)Zenmap',
        '(?i)Wireshark', '(?i)tcpdump',
        '(?i)Cygwin', '(?i)MinGW',
        '(?i)Windows Subsystem for Linux', '(?i)WSL',
        '(?i)Metasploit', '(?i)Burp\s*Suite', '(?i)OWASP\s*ZAP',
        '(?i)Hashcat', '(?i)John\s*the\s*Ripper',
        '(?i)Aircrack', '(?i)Ettercap',
        '(?i)Sysinternals', '(?i)Process\s*Hacker',
        '(?i)Putty', '(?i)WinSCP',
        '(?i)Netcat', '(?i)ncat',
        '(?i)Tor\s*Browser',
        '(?i)ProxyChains', '(?i)Proxifier'
    )

    $devToolsFound = @()
    foreach ($sw in $softwareItems) {
        foreach ($pattern in $devToolPatterns) {
            if ($sw.Name -match $pattern) {
                $entry = $sw.Name
                if (-not [string]::IsNullOrWhiteSpace($sw.Version)) { $entry += " v$($sw.Version)" }
                $devToolsFound += $entry
                break
            }
        }
    }

    if ($devToolsFound.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSOFT-002' -Severity 'Medium' -Category 'Software' `
            -Title "Development or security tools installed ($($devToolsFound.Count) found)" `
            -Description "Found $($devToolsFound.Count) development, networking, or security tool(s). While these may be legitimate, they can also indicate reconnaissance or attack preparation." `
            -ArtifactPath 'software/installed_software.csv' `
            -Evidence @($devToolsFound | Select-Object -First 15) `
            -Recommendation 'Verify all development and security tools are authorized for this system. On production servers, these tools are typically unnecessary and should be removed.' `
            -MITRE 'T1588.002' `
            -CVSSv3Score '5.3' `
            -TechnicalImpact 'Development and security tools can be leveraged for network reconnaissance, credential cracking, traffic interception, and exploitation.'))
    }

    # ----------------------------------------------------------------
    # WSOFT-003: No security patches in last 90 days
    # ----------------------------------------------------------------
    $hotfixPath = Join-Path $EvidencePath 'software/hotfixes.csv'
    $patchAgeDays = 90
    if ($Rules.ContainsKey('max_patch_age_days')) { $patchAgeDays = [int]$Rules['max_patch_age_days'] }

    if (Test-Path $hotfixPath) {
        try {
            $hotfixes = Import-Csv -Path $hotfixPath -ErrorAction Stop
            $recentPatches = @()
            $allPatches = @()

            foreach ($hf in $hotfixes) {
                $installedOn = $null
                foreach ($dateField in @('InstalledOn', 'InstallDate', 'Date', 'Installed')) {
                    if ($hf.PSObject.Properties[$dateField] -and -not [string]::IsNullOrWhiteSpace($hf.$dateField)) {
                        try { $installedOn = [datetime]::Parse($hf.$dateField) } catch { }
                        if ($null -ne $installedOn) { break }
                    }
                }

                $hfId = ''
                if ($hf.PSObject.Properties['HotFixID']) { $hfId = $hf.HotFixID }
                elseif ($hf.PSObject.Properties['HotfixId']) { $hfId = $hf.HotfixId }
                elseif ($hf.PSObject.Properties['KB']) { $hfId = $hf.KB }

                $desc = ''
                if ($hf.PSObject.Properties['Description']) { $desc = $hf.Description }

                $allPatches += [PSCustomObject]@{
                    Id          = $hfId
                    Description = $desc
                    InstalledOn = $installedOn
                }

                if ($null -ne $installedOn) {
                    $age = (Get-Date) - $installedOn
                    if ($age.TotalDays -le $patchAgeDays) {
                        $recentPatches += [PSCustomObject]@{
                            Id          = $hfId
                            Description = $desc
                            InstalledOn = $installedOn
                        }
                    }
                }
            }

            if ($recentPatches.Count -eq 0 -and $allPatches.Count -gt 0) {
                $latestPatch = $allPatches | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
                $patchEvidence = @("Total patches found: $($allPatches.Count)")
                $patchEvidence += "No patches installed in the last $patchAgeDays days"
                if ($null -ne $latestPatch -and $null -ne $latestPatch.InstalledOn) {
                    $daysSince = [math]::Round(((Get-Date) - $latestPatch.InstalledOn).TotalDays, 0)
                    $patchEvidence += "Last patch: $($latestPatch.Id) installed on $($latestPatch.InstalledOn.ToString('yyyy-MM-dd')) ($daysSince days ago)"
                }

                $findings.Add((New-Finding -Id 'WSOFT-003' -Severity 'High' -Category 'Software' `
                    -Title "No security patches installed in the last $patchAgeDays days" `
                    -Description "No Windows hotfixes or security patches have been installed in the last $patchAgeDays days. The system may be vulnerable to known exploits." `
                    -ArtifactPath 'software/hotfixes.csv' `
                    -Evidence $patchEvidence `
                    -Recommendation "Apply all pending security updates immediately. Investigate why patching has stopped and ensure Windows Update is functioning." `
                    -MITRE 'T1190' `
                    -CVSSv3Score '8.1' `
                    -TechnicalImpact "Unpatched systems are vulnerable to publicly known exploits that may allow remote code execution, privilege escalation, or data theft."))
            }
        }
        catch {
            Write-Verbose "Failed to parse hotfixes.csv: $_"
        }
    }

    # ----------------------------------------------------------------
    # WSOFT-004: End-of-life software detected
    # ----------------------------------------------------------------
    $eolPatterns = @(
        @{ Pattern = '(?i)Windows\s+(7|8|8\.1|Vista|XP)'; Name = 'Windows client OS' },
        @{ Pattern = '(?i)Windows\s+Server\s+(2003|2008|2012)\b'; Name = 'Windows Server' },
        @{ Pattern = '(?i)Microsoft\s+Office\s+(2003|2007|2010|2013)\b'; Name = 'Microsoft Office' },
        @{ Pattern = '(?i)Internet\s+Explorer\b'; Name = 'Internet Explorer' },
        @{ Pattern = '(?i)Adobe\s+Flash\s+Player'; Name = 'Adobe Flash Player' },
        @{ Pattern = '(?i)Java\s+(6|7|8)\b(?!.*Update\s*(3[5-9][0-9]|[4-9]\d{2}))'; Name = 'Java (old version)' },
        @{ Pattern = '(?i)\.NET\s+Framework\s+[1-3]\.'; Name = '.NET Framework (old version)' },
        @{ Pattern = '(?i)SQL\s+Server\s+(2005|2008|2012)\b'; Name = 'SQL Server' },
        @{ Pattern = '(?i)Exchange\s+Server\s+(2010|2013)\b'; Name = 'Exchange Server' },
        @{ Pattern = '(?i)Silverlight'; Name = 'Microsoft Silverlight' },
        @{ Pattern = '(?i)Visual\s+Basic\s+6'; Name = 'Visual Basic 6' }
    )

    $eolFound = @()
    foreach ($sw in $softwareItems) {
        foreach ($eol in $eolPatterns) {
            if ($sw.Name -match $eol.Pattern) {
                $entry = "$($eol.Name): $($sw.Name)"
                if (-not [string]::IsNullOrWhiteSpace($sw.Version)) { $entry += " v$($sw.Version)" }
                $eolFound += $entry
                break
            }
        }
    }

    if ($eolFound.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSOFT-004' -Severity 'Medium' -Category 'Software' `
            -Title "End-of-life software detected ($($eolFound.Count) found)" `
            -Description "Found $($eolFound.Count) end-of-life software product(s). EOL software no longer receives security updates, leaving known vulnerabilities permanently unpatched." `
            -ArtifactPath 'software/installed_software.csv' `
            -Evidence @($eolFound | Select-Object -First 15) `
            -Recommendation 'Upgrade or replace end-of-life software with supported versions. If upgrade is not possible, isolate the system and implement compensating controls.' `
            -MITRE 'T1190' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'End-of-life software contains known unpatched vulnerabilities that attackers can exploit for remote code execution and system compromise.'))
    }

    # ----------------------------------------------------------------
    # WSOFT-005: Known vulnerable software (outdated common software)
    # ----------------------------------------------------------------
    $vulnerableChecks = @(
        @{ Pattern = '(?i)Adobe\s+(Acrobat|Reader)'; MinVersion = '23.0'; Name = 'Adobe Acrobat/Reader' },
        @{ Pattern = '(?i)7-Zip'; MinVersion = '23.0'; Name = '7-Zip' },
        @{ Pattern = '(?i)WinRAR'; MinVersion = '6.2'; Name = 'WinRAR' },
        @{ Pattern = '(?i)Google\s+Chrome'; MinVersion = '120.0'; Name = 'Google Chrome' },
        @{ Pattern = '(?i)Mozilla\s+Firefox'; MinVersion = '120.0'; Name = 'Mozilla Firefox' },
        @{ Pattern = '(?i)Apache'; MinVersion = '2.4.58'; Name = 'Apache HTTP Server' },
        @{ Pattern = '(?i)OpenSSL'; MinVersion = '3.0'; Name = 'OpenSSL' },
        @{ Pattern = '(?i)OpenSSH'; MinVersion = '9.0'; Name = 'OpenSSH' },
        @{ Pattern = '(?i)PuTTY'; MinVersion = '0.80'; Name = 'PuTTY' },
        @{ Pattern = '(?i)FileZilla'; MinVersion = '3.65'; Name = 'FileZilla' },
        @{ Pattern = '(?i)Notepad\+\+'; MinVersion = '8.6'; Name = 'Notepad++' },
        @{ Pattern = '(?i)Log4j'; MinVersion = '2.18'; Name = 'Log4j' }
    )

    $vulnerableFound = @()
    foreach ($sw in $softwareItems) {
        if ([string]::IsNullOrWhiteSpace($sw.Version)) { continue }

        foreach ($check in $vulnerableChecks) {
            if ($sw.Name -match $check.Pattern) {
                # Compare versions
                try {
                    # Extract leading version numbers
                    $currentVer = $null
                    $minVer = $null
                    if ($sw.Version -match '^(\d+(\.\d+)*)') {
                        $currentVer = [version]$Matches[1]
                    }
                    $minVer = [version]$check.MinVersion

                    if ($null -ne $currentVer -and $null -ne $minVer -and $currentVer -lt $minVer) {
                        $vulnerableFound += "$($check.Name): installed v$($sw.Version), minimum recommended v$($check.MinVersion)"
                    }
                }
                catch {
                    Write-Verbose "Version comparison failed for $($sw.Name): $_"
                }
                break
            }
        }
    }

    if ($vulnerableFound.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WSOFT-005' -Severity 'Medium' -Category 'Software' `
            -Title "Potentially vulnerable software versions detected ($($vulnerableFound.Count) found)" `
            -Description "Found $($vulnerableFound.Count) software product(s) running versions older than recommended minimums. These versions may contain known vulnerabilities." `
            -ArtifactPath 'software/installed_software.csv' `
            -Evidence @($vulnerableFound | Select-Object -First 15) `
            -Recommendation 'Update all flagged software to the latest stable versions. Check vendor advisories for known CVEs affecting the installed versions.' `
            -MITRE 'T1190' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact 'Outdated software versions may contain known exploitable vulnerabilities that can be leveraged for initial access or privilege escalation.'))
    }

    # ----------------------------------------------------------------
    # WSOFT-006: Software summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()
    $summaryItems += "Total software items found: $($softwareItems.Count)"

    # Count by source
    $bySource = $softwareItems | Group-Object -Property Source
    foreach ($group in $bySource) {
        $summaryItems += "Source '$($group.Name)': $($group.Count) items"
    }

    # Top publishers
    $withPublisher = $softwareItems | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Publisher) }
    if ($withPublisher.Count -gt 0) {
        $topPublishers = $withPublisher | Group-Object -Property Publisher | Sort-Object Count -Descending | Select-Object -First 5
        foreach ($pub in $topPublishers) {
            $summaryItems += "Publisher '$($pub.Name)': $($pub.Count) products"
        }
    }

    # Hotfix summary
    if (Test-Path $hotfixPath) {
        try {
            $hfCount = (Import-Csv -Path $hotfixPath -ErrorAction Stop).Count
            $summaryItems += "Hotfixes/patches installed: $hfCount"
        }
        catch {
            $summaryItems += 'Hotfixes: unable to parse'
        }
    }
    else {
        $summaryItems += 'Hotfixes file not found'
    }

    $summaryItems += "Remote access tools: $($remoteAccessFound.Count)"
    $summaryItems += "Development/security tools: $($devToolsFound.Count)"
    $summaryItems += "End-of-life software: $($eolFound.Count)"
    $summaryItems += "Potentially vulnerable versions: $($vulnerableFound.Count)"

    $findings.Add((New-Finding -Id 'WSOFT-006' -Severity 'Informational' -Category 'Software' `
        -Title 'Installed software summary' `
        -Description 'Summary of installed software analysis including remote access tools, development tools, patches, and version checks.' `
        -ArtifactPath 'software/installed_software.csv' `
        -Evidence $summaryItems `
        -Recommendation 'Review the software inventory and ensure all installed software is authorized and up to date.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of installed software posture.'))

    return $findings.ToArray()
}
