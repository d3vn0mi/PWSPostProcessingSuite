function Invoke-WindowsArtifactCollector {
    <#
    .SYNOPSIS
        Collects forensic artifacts from a live Windows system into a structured evidence directory.
    .DESCRIPTION
        Gathers registry keys, event logs, configuration, network state, services, scheduled tasks,
        and command outputs from the local Windows system. Stores them in a structured layout that
        Windows security analyzers can process directly.
    .PARAMETER OutputPath
        Root directory where collected artifacts will be stored.
    .PARAMETER IncludeCategories
        Collect only these categories. Default: all categories.
    .PARAMETER ExcludeCategories
        Skip these categories during collection.
    .PARAMETER SkipCommands
        Skip running live commands (only collect registry/files). Useful for restricted environments.
    .PARAMETER MaxEventLogEntries
        Maximum number of event log entries to export per log. Default: 5000.
    .PARAMETER CollectUserProfiles
        Include per-user artifacts (NTUSER registry, PSReadline history, etc.). Off by default.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string[]]$IncludeCategories,

        [string[]]$ExcludeCategories,

        [switch]$SkipCommands,

        [int]$MaxEventLogEntries = 5000,

        [switch]$CollectUserProfiles
    )

    $collectionStart = Get-Date
    $stats = @{ FilesCopied = 0; CommandsRun = 0; Errors = 0; Skipped = 0; BytesCollected = 0 }

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Windows Artifact Collector - Live Evidence Gathering" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[*] Output path: $OutputPath" -ForegroundColor White
    Write-Host "[*] Collection started: $collectionStart" -ForegroundColor White
    Write-Host ""

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # =========================================================================
    # Helper: Ensure a directory exists under the output path
    # =========================================================================
    function Ensure-CollectionDir {
        param([string]$SubDir)
        $fullPath = Join-Path $OutputPath $SubDir
        if (-not (Test-Path $fullPath)) {
            New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        }
        return $fullPath
    }

    # =========================================================================
    # Helper: Export registry key properties to a text file
    # =========================================================================
    function Export-RegistryKey {
        param(
            [string]$KeyPath,
            [string]$OutputFile
        )

        $destDir = Split-Path $OutputFile -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        try {
            if (-not (Test-Path $KeyPath -ErrorAction SilentlyContinue)) {
                return $false
            }

            $lines = @()
            $lines += "Registry Key: $KeyPath"
            $lines += "Exported: $(Get-Date)"
            $lines += "=" * 70

            # Get properties of the key itself
            $props = Get-ItemProperty -Path $KeyPath -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
                } | ForEach-Object {
                    $lines += "$($_.Name) = $($_.Value)"
                }
            }

            # Get subkeys
            $subKeys = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue
            if ($subKeys) {
                $lines += ""
                $lines += "Subkeys:"
                foreach ($sub in $subKeys) {
                    $lines += "  $($sub.PSChildName)"
                    try {
                        $subProps = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
                        if ($subProps) {
                            $subProps.PSObject.Properties | Where-Object {
                                $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
                            } | ForEach-Object {
                                $lines += "    $($_.Name) = $($_.Value)"
                            }
                        }
                    }
                    catch { }
                }
            }

            $lines | Out-File -FilePath $OutputFile -Force -Encoding utf8
            $script:stats['BytesCollected'] += (Get-Item $OutputFile -ErrorAction SilentlyContinue).Length
            return $true
        }
        catch {
            Write-Verbose "  Could not export registry key $KeyPath : $_"
            return $false
        }
    }

    # =========================================================================
    # Helper: Run a command and save output to file
    # =========================================================================
    function Save-CommandOutput {
        param(
            [string]$Name,
            [scriptblock]$ScriptBlock,
            [string]$OutputFile
        )

        $destDir = Split-Path $OutputFile -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        try {
            $result = & $ScriptBlock 2>&1
            if ($null -ne $result) {
                $result | Out-File -FilePath $OutputFile -Force -Encoding utf8
                $script:stats['CommandsRun']++
                $script:stats['BytesCollected'] += (Get-Item $OutputFile -ErrorAction SilentlyContinue).Length
                return $true
            }
            return $false
        }
        catch {
            Write-Verbose "  Command failed ($Name): $_"
            return $false
        }
    }

    # =========================================================================
    # Helper: Export event log entries to CSV
    # =========================================================================
    function Export-EventLogEntries {
        param(
            [string]$LogName,
            [string]$OutputFile,
            [int]$MaxEntries,
            [hashtable]$FilterHash = $null
        )

        $destDir = Split-Path $OutputFile -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        try {
            $params = @{
                LogName     = $LogName
                MaxEvents   = $MaxEntries
                ErrorAction = 'SilentlyContinue'
            }
            if ($FilterHash) {
                $params.Remove('LogName')
                $params['FilterHashtable'] = $FilterHash
            }

            $events = Get-WinEvent @params
            if ($events) {
                $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
                    Export-Csv -Path $OutputFile -NoTypeInformation -Force -Encoding utf8
                $script:stats['BytesCollected'] += (Get-Item $OutputFile -ErrorAction SilentlyContinue).Length
                return $events.Count
            }
            return 0
        }
        catch {
            Write-Verbose "  Could not export event log $LogName : $_"
            return 0
        }
    }

    # =========================================================================
    # Define all collection categories
    # =========================================================================
    $allCategories = [ordered]@{

        # -----------------------------------------------------------------
        # 1. User Accounts & Authentication
        # -----------------------------------------------------------------
        'UserAccounts' = @{
            Description = 'User accounts, groups, and password policy'
        }

        # -----------------------------------------------------------------
        # 2. Registry Persistence Mechanisms
        # -----------------------------------------------------------------
        'RegistryPersistence' = @{
            Description = 'Registry autorun keys and persistence mechanisms'
        }

        # -----------------------------------------------------------------
        # 3. Scheduled Tasks
        # -----------------------------------------------------------------
        'ScheduledTasks' = @{
            Description = 'Scheduled tasks configuration and history'
        }

        # -----------------------------------------------------------------
        # 4. Services
        # -----------------------------------------------------------------
        'Services' = @{
            Description = 'Windows services, startup types, and binary paths'
        }

        # -----------------------------------------------------------------
        # 5. Firewall
        # -----------------------------------------------------------------
        'Firewall' = @{
            Description = 'Windows Firewall profiles and rules'
        }

        # -----------------------------------------------------------------
        # 6. Network Configuration
        # -----------------------------------------------------------------
        'NetworkConfig' = @{
            Description = 'Network interfaces, connections, and routing'
        }

        # -----------------------------------------------------------------
        # 7. Security Event Log
        # -----------------------------------------------------------------
        'SecurityEventLog' = @{
            Description = 'Security event log (logon, privilege, account mgmt)'
        }

        # -----------------------------------------------------------------
        # 8. System Event Log
        # -----------------------------------------------------------------
        'SystemEventLog' = @{
            Description = 'System event log entries'
        }

        # -----------------------------------------------------------------
        # 9. PowerShell Log
        # -----------------------------------------------------------------
        'PowerShellLog' = @{
            Description = 'PowerShell operational and script block logs'
        }

        # -----------------------------------------------------------------
        # 10. Group Policy & Audit Policy
        # -----------------------------------------------------------------
        'GroupPolicy' = @{
            Description = 'Group policy results, security policy, and audit config'
        }

        # -----------------------------------------------------------------
        # 11. Shares
        # -----------------------------------------------------------------
        'Shares' = @{
            Description = 'SMB shares and share permissions'
        }

        # -----------------------------------------------------------------
        # 12. Installed Software
        # -----------------------------------------------------------------
        'InstalledSoftware' = @{
            Description = 'Installed programs, hotfixes, and updates'
        }

        # -----------------------------------------------------------------
        # 13. Windows Defender
        # -----------------------------------------------------------------
        'WindowsDefender' = @{
            Description = 'Windows Defender status, exclusions, and detections'
        }

        # -----------------------------------------------------------------
        # 14. RDP Configuration
        # -----------------------------------------------------------------
        'RDPConfig' = @{
            Description = 'Remote Desktop configuration and recent connections'
        }

        # -----------------------------------------------------------------
        # 15. WMI Persistence
        # -----------------------------------------------------------------
        'WMIPersistence' = @{
            Description = 'WMI event subscriptions and persistence bindings'
        }

        # -----------------------------------------------------------------
        # 16. Certificates
        # -----------------------------------------------------------------
        'Certificates' = @{
            Description = 'Certificate stores and trusted root certificates'
        }

        # -----------------------------------------------------------------
        # 17. AutoStart Locations
        # -----------------------------------------------------------------
        'AutoStart' = @{
            Description = 'Startup folder contents and shell startup items'
        }

        # -----------------------------------------------------------------
        # 18. DLL Security & AppLocker
        # -----------------------------------------------------------------
        'DLLSecurity' = @{
            Description = 'Known DLLs, PATH writability, and AppLocker/WDAC policies'
        }

        # -----------------------------------------------------------------
        # 19. BitLocker
        # -----------------------------------------------------------------
        'BitLocker' = @{
            Description = 'BitLocker volume encryption status'
        }

        # -----------------------------------------------------------------
        # 20. SMB Configuration
        # -----------------------------------------------------------------
        'SMBConfig' = @{
            Description = 'SMB server/client configuration and SMBv1 status'
        }

        # -----------------------------------------------------------------
        # 21. DNS Cache
        # -----------------------------------------------------------------
        'DNSCache' = @{
            Description = 'DNS client cache entries'
        }

        # -----------------------------------------------------------------
        # 22. Process Information
        # -----------------------------------------------------------------
        'ProcessInfo' = @{
            Description = 'Running processes with command lines and details'
        }
    }

    # =========================================================================
    # Filter categories
    # =========================================================================
    $categoriesToRun = $allCategories.Keys | ForEach-Object { $_ }
    if ($IncludeCategories) {
        $categoriesToRun = $categoriesToRun | Where-Object { $_ -in $IncludeCategories }
    }
    if ($ExcludeCategories) {
        $categoriesToRun = $categoriesToRun | Where-Object { $_ -notin $ExcludeCategories }
    }

    Write-Host "[*] Collecting $($categoriesToRun.Count) categories..." -ForegroundColor White
    Write-Host ""

    # =========================================================================
    # Discover user profile directories (if requested)
    # =========================================================================
    $userProfiles = @()
    if ($CollectUserProfiles) {
        try {
            $profilesRoot = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue).ProfilesDirectory
            if (-not $profilesRoot) { $profilesRoot = "$env:SystemDrive\Users" }
            $userProfiles = Get-ChildItem -Path $profilesRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
        }
        catch {
            # Fallback
            $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
        }
        Write-Host "[*] Found $($userProfiles.Count) user profiles" -ForegroundColor White
    }

    # =========================================================================
    # Process each category
    # =========================================================================
    foreach ($catName in $categoriesToRun) {
        $cat = $allCategories[$catName]
        Write-Host "  [>] $catName - $($cat.Description)..." -ForegroundColor DarkGray -NoNewline

        $catCopied = 0
        $catErrors = 0

        switch ($catName) {

            # =================================================================
            # 1. UserAccounts
            # =================================================================
            'UserAccounts' {
                $usersDir = Ensure-CollectionDir 'users'
                $cmdDir   = Ensure-CollectionDir 'collected_commands'

                # Get-LocalUser
                try {
                    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
                    if ($localUsers) {
                        $localUsers | Format-Table -AutoSize -Property Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, Description |
                            Out-File -FilePath (Join-Path $usersDir 'local_users.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-LocalGroup
                try {
                    $localGroups = Get-LocalGroup -ErrorAction SilentlyContinue
                    if ($localGroups) {
                        $localGroups | Format-Table -AutoSize -Property Name, Description |
                            Out-File -FilePath (Join-Path $usersDir 'local_groups.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }

                    # Members of each group
                    foreach ($group in $localGroups) {
                        try {
                            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
                            if ($members) {
                                $safeName = $group.Name -replace '[\\/:*?"<>|]', '_'
                                $members | Format-Table -AutoSize -Property Name, ObjectClass, PrincipalSource |
                                    Out-File -FilePath (Join-Path $usersDir "group_members_$safeName.txt") -Force -Encoding utf8
                                $catCopied++; $stats['FilesCopied']++
                            }
                        }
                        catch { }
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # net user
                    $saved = Save-CommandOutput -Name 'net_user' -ScriptBlock { net user } `
                        -OutputFile (Join-Path $cmdDir 'net_user.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # net localgroup administrators
                    $saved = Save-CommandOutput -Name 'net_localgroup_admins' -ScriptBlock { net localgroup administrators } `
                        -OutputFile (Join-Path $cmdDir 'net_localgroup_administrators.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # whoami /all
                    $saved = Save-CommandOutput -Name 'whoami_all' -ScriptBlock { whoami /all } `
                        -OutputFile (Join-Path $cmdDir 'whoami_all.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # net accounts (password policy)
                    $saved = Save-CommandOutput -Name 'net_accounts' -ScriptBlock { net accounts } `
                        -OutputFile (Join-Path $cmdDir 'net_accounts.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 2. RegistryPersistence
            # =================================================================
            'RegistryPersistence' {
                $regDir = Ensure-CollectionDir 'registry'
                $svcDir = Ensure-CollectionDir 'services'

                $registryKeys = @(
                    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';           File = 'hklm_run.txt' }
                    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';       File = 'hklm_runonce.txt' }
                    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';           File = 'hkcu_run.txt' }
                    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';       File = 'hkcu_runonce.txt' }
                    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';   File = 'winlogon.txt' }
                    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'; File = 'appcertdlls.txt' }
                    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; File = 'ifeo.txt' }
                )

                foreach ($regKey in $registryKeys) {
                    $exported = Export-RegistryKey -KeyPath $regKey.Path -OutputFile (Join-Path $regDir $regKey.File)
                    if ($exported) {
                        $catCopied++; $stats['FilesCopied']++
                    }
                    else {
                        $stats['Skipped']++
                    }
                }

                # CLSID - just enumerate top-level subkeys (do not dump all properties)
                try {
                    $clsidPath = 'HKLM:\SOFTWARE\Classes\CLSID'
                    if (Test-Path $clsidPath -ErrorAction SilentlyContinue) {
                        $clsidKeys = Get-ChildItem -Path $clsidPath -ErrorAction SilentlyContinue | Select-Object -First 500
                        if ($clsidKeys) {
                            $lines = @("Registry Key: $clsidPath", "Exported: $(Get-Date)", "=" * 70, "", "CLSID Entries (first 500):")
                            foreach ($ck in $clsidKeys) {
                                $defaultVal = (Get-ItemProperty -Path $ck.PSPath -ErrorAction SilentlyContinue).'(default)'
                                $displayName = if ($defaultVal) { " = $defaultVal" } else { '' }
                                $lines += "  $($ck.PSChildName)$displayName"
                            }
                            $lines | Out-File -FilePath (Join-Path $regDir 'clsid_enum.txt') -Force -Encoding utf8
                            $catCopied++; $stats['FilesCopied']++
                        }
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Services registry key
                $exported = Export-RegistryKey -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Services' `
                    -OutputFile (Join-Path $svcDir 'services_registry.txt')
                if ($exported) {
                    $catCopied++; $stats['FilesCopied']++
                }
                else {
                    $stats['Skipped']++
                }
            }

            # =================================================================
            # 3. ScheduledTasks
            # =================================================================
            'ScheduledTasks' {
                $taskDir = Ensure-CollectionDir 'tasks'
                $cmdDir  = Ensure-CollectionDir 'collected_commands'

                # Get-ScheduledTask export
                try {
                    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
                    if ($tasks) {
                        $tasks | Select-Object TaskName, TaskPath, State, Description,
                            @{N='Actions';E={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ' }},
                            @{N='Triggers';E={ ($_.Triggers | ForEach-Object { $_.ToString() }) -join '; ' }},
                            @{N='RunAs';E={ $_.Principal.UserId }} |
                            Export-Csv -Path (Join-Path $taskDir 'scheduled_tasks.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $taskDir 'scheduled_tasks.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # schtasks verbose CSV
                    $saved = Save-CommandOutput -Name 'schtasks_csv' -ScriptBlock { schtasks /query /fo CSV /v } `
                        -OutputFile (Join-Path $cmdDir 'schtasks_verbose.csv')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 4. Services
            # =================================================================
            'Services' {
                $svcDir = Ensure-CollectionDir 'services'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Get-Service
                try {
                    $services = Get-Service -ErrorAction SilentlyContinue
                    if ($services) {
                        $services | Format-Table -AutoSize -Property Name, DisplayName, Status, StartType |
                            Out-File -FilePath (Join-Path $svcDir 'services_list.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-CimInstance Win32_Service (includes PathName, StartMode)
                try {
                    $cimServices = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
                    if ($cimServices) {
                        $cimServices | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description |
                            Export-Csv -Path (Join-Path $svcDir 'services_detailed.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $svcDir 'services_detailed.csv') -ErrorAction SilentlyContinue).Length

                        # Check for unquoted service paths
                        $unquoted = $cimServices | Where-Object {
                            $_.PathName -and
                            $_.PathName -notmatch '^"' -and
                            $_.PathName -notmatch '^\w:\\Windows\\' -and
                            $_.PathName -match '\s'
                        }
                        if ($unquoted) {
                            $unquoted | Select-Object Name, PathName, StartMode, StartName |
                                Format-Table -AutoSize |
                                Out-File -FilePath (Join-Path $svcDir 'unquoted_service_paths.txt') -Force -Encoding utf8
                            $catCopied++; $stats['FilesCopied']++
                        }
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 5. Firewall
            # =================================================================
            'Firewall' {
                $fwDir  = Ensure-CollectionDir 'firewall'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Get-NetFirewallProfile
                try {
                    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                    if ($fwProfiles) {
                        $fwProfiles | Format-List |
                            Out-File -FilePath (Join-Path $fwDir 'firewall_profiles.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-NetFirewallRule (enabled rules)
                try {
                    $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue
                    if ($fwRules) {
                        $fwRules | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile |
                            Export-Csv -Path (Join-Path $fwDir 'firewall_rules.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $fwDir 'firewall_rules.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # netsh advfirewall show allprofiles
                    $saved = Save-CommandOutput -Name 'netsh_fw_profiles' -ScriptBlock { netsh advfirewall show allprofiles } `
                        -OutputFile (Join-Path $cmdDir 'netsh_advfirewall_profiles.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # netsh advfirewall firewall show rule name=all
                    $saved = Save-CommandOutput -Name 'netsh_fw_rules' -ScriptBlock { netsh advfirewall firewall show rule name=all } `
                        -OutputFile (Join-Path $cmdDir 'netsh_advfirewall_rules.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 6. NetworkConfig
            # =================================================================
            'NetworkConfig' {
                $netDir = Ensure-CollectionDir 'network'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Get-NetIPAddress
                try {
                    $ipAddrs = Get-NetIPAddress -ErrorAction SilentlyContinue
                    if ($ipAddrs) {
                        $ipAddrs | Format-Table -AutoSize -Property InterfaceAlias, IPAddress, PrefixLength, AddressFamily |
                            Out-File -FilePath (Join-Path $netDir 'ip_addresses.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-DnsClientServerAddress
                try {
                    $dnsServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
                    if ($dnsServers) {
                        $dnsServers | Format-Table -AutoSize -Property InterfaceAlias, ServerAddresses, AddressFamily |
                            Out-File -FilePath (Join-Path $netDir 'dns_servers.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-NetTCPConnection
                try {
                    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
                    if ($tcpConns) {
                        $tcpConns | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
                            Export-Csv -Path (Join-Path $netDir 'tcp_connections.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $netDir 'tcp_connections.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # ipconfig /all
                    $saved = Save-CommandOutput -Name 'ipconfig_all' -ScriptBlock { ipconfig /all } `
                        -OutputFile (Join-Path $cmdDir 'ipconfig_all.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # netstat -ano
                    $saved = Save-CommandOutput -Name 'netstat_ano' -ScriptBlock { netstat -ano } `
                        -OutputFile (Join-Path $cmdDir 'netstat_ano.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # arp -a
                    $saved = Save-CommandOutput -Name 'arp_a' -ScriptBlock { arp -a } `
                        -OutputFile (Join-Path $cmdDir 'arp_table.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # route print
                    $saved = Save-CommandOutput -Name 'route_print' -ScriptBlock { route print } `
                        -OutputFile (Join-Path $cmdDir 'route_print.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # nslookup
                    $saved = Save-CommandOutput -Name 'nslookup' -ScriptBlock { nslookup localhost } `
                        -OutputFile (Join-Path $cmdDir 'nslookup.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 7. SecurityEventLog
            # =================================================================
            'SecurityEventLog' {
                $logDir = Ensure-CollectionDir 'eventlogs'

                # Logon events (4624, 4625, 4634)
                try {
                    $count = Export-EventLogEntries -LogName 'Security' `
                        -OutputFile (Join-Path $logDir 'security_logon_events.csv') `
                        -MaxEntries $MaxEventLogEntries `
                        -FilterHash @{ LogName = 'Security'; Id = @(4624, 4625, 4634); }
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Privilege use (4672, 4673)
                try {
                    $count = Export-EventLogEntries -LogName 'Security' `
                        -OutputFile (Join-Path $logDir 'security_privilege_events.csv') `
                        -MaxEntries $MaxEventLogEntries `
                        -FilterHash @{ LogName = 'Security'; Id = @(4672, 4673); }
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Account management (4720-4738)
                try {
                    $acctMgmtIds = 4720..4738
                    $count = Export-EventLogEntries -LogName 'Security' `
                        -OutputFile (Join-Path $logDir 'security_account_mgmt_events.csv') `
                        -MaxEntries $MaxEventLogEntries `
                        -FilterHash @{ LogName = 'Security'; Id = $acctMgmtIds; }
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Policy changes (4719)
                try {
                    $count = Export-EventLogEntries -LogName 'Security' `
                        -OutputFile (Join-Path $logDir 'security_policy_change_events.csv') `
                        -MaxEntries $MaxEventLogEntries `
                        -FilterHash @{ LogName = 'Security'; Id = @(4719); }
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 8. SystemEventLog
            # =================================================================
            'SystemEventLog' {
                $logDir = Ensure-CollectionDir 'eventlogs'

                try {
                    $count = Export-EventLogEntries -LogName 'System' `
                        -OutputFile (Join-Path $logDir 'system_events.csv') `
                        -MaxEntries $MaxEventLogEntries
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 9. PowerShellLog
            # =================================================================
            'PowerShellLog' {
                $logDir = Ensure-CollectionDir 'eventlogs'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # PowerShell Operational log
                try {
                    $count = Export-EventLogEntries -LogName 'Microsoft-Windows-PowerShell/Operational' `
                        -OutputFile (Join-Path $logDir 'powershell_operational.csv') `
                        -MaxEntries $MaxEventLogEntries `
                        -FilterHash @{ LogName = 'Microsoft-Windows-PowerShell/Operational' }
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Script Block logging (Event ID 4104)
                try {
                    $count = Export-EventLogEntries -LogName 'Microsoft-Windows-PowerShell/Operational' `
                        -OutputFile (Join-Path $logDir 'powershell_scriptblock.csv') `
                        -MaxEntries $MaxEventLogEntries `
                        -FilterHash @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = @(4104); }
                    if ($count -gt 0) { $catCopied++; $stats['FilesCopied']++ }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # PSReadline history files
                if ($CollectUserProfiles) {
                    foreach ($profile in $userProfiles) {
                        $historyPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                        if (Test-Path $historyPath -ErrorAction SilentlyContinue) {
                            try {
                                $destFile = Join-Path $logDir "psreadline_history_$($profile.Name).txt"
                                Copy-Item -Path $historyPath -Destination $destFile -Force -ErrorAction Stop
                                $catCopied++; $stats['FilesCopied']++
                                $stats['BytesCollected'] += (Get-Item $destFile -ErrorAction SilentlyContinue).Length
                            }
                            catch { $catErrors++; $stats['Errors']++ }
                        }
                    }
                }
                else {
                    # At minimum collect current user's PSReadline history
                    $currentHistory = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                    if (Test-Path $currentHistory -ErrorAction SilentlyContinue) {
                        try {
                            $destFile = Join-Path $logDir 'psreadline_history_current_user.txt'
                            Copy-Item -Path $currentHistory -Destination $destFile -Force -ErrorAction Stop
                            $catCopied++; $stats['FilesCopied']++
                            $stats['BytesCollected'] += (Get-Item $destFile -ErrorAction SilentlyContinue).Length
                        }
                        catch { $catErrors++; $stats['Errors']++ }
                    }
                }
            }

            # =================================================================
            # 10. GroupPolicy
            # =================================================================
            'GroupPolicy' {
                $secDir = Ensure-CollectionDir 'security'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                if (-not $SkipCommands) {
                    # gpresult /R
                    $saved = Save-CommandOutput -Name 'gpresult' -ScriptBlock { gpresult /R } `
                        -OutputFile (Join-Path $cmdDir 'gpresult.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }

                    # secedit /export
                    $secEditFile = Join-Path $secDir 'secpol_export.cfg'
                    try {
                        $null = secedit /export /cfg $secEditFile 2>&1
                        if (Test-Path $secEditFile) {
                            $catCopied++; $stats['FilesCopied']++
                            $stats['BytesCollected'] += (Get-Item $secEditFile -ErrorAction SilentlyContinue).Length
                        }
                    }
                    catch { $catErrors++; $stats['Errors']++ }

                    # auditpol /get /category:*
                    $saved = Save-CommandOutput -Name 'auditpol' -ScriptBlock { auditpol /get /category:* } `
                        -OutputFile (Join-Path $secDir 'audit_policy.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 11. Shares
            # =================================================================
            'Shares' {
                $netDir = Ensure-CollectionDir 'network'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Get-SmbShare
                try {
                    $shares = Get-SmbShare -ErrorAction SilentlyContinue
                    if ($shares) {
                        $shares | Format-Table -AutoSize -Property Name, Path, Description, CurrentUsers |
                            Out-File -FilePath (Join-Path $netDir 'smb_shares.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++

                        # Share permissions
                        foreach ($share in $shares) {
                            try {
                                $perms = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                                if ($perms) {
                                    $perms | Format-Table -AutoSize |
                                        Out-File -FilePath (Join-Path $netDir "share_permissions_$($share.Name).txt") -Force -Encoding utf8 -Append
                                }
                            }
                            catch { }
                        }
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    $saved = Save-CommandOutput -Name 'net_share' -ScriptBlock { net share } `
                        -OutputFile (Join-Path $cmdDir 'net_share.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 12. InstalledSoftware
            # =================================================================
            'InstalledSoftware' {
                $swDir  = Ensure-CollectionDir 'software'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Registry uninstall keys (64-bit)
                try {
                    $uninstallPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    $software = Get-ItemProperty -Path $uninstallPath -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString
                    if ($software) {
                        $software | Export-Csv -Path (Join-Path $swDir 'installed_software_64bit.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $swDir 'installed_software_64bit.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Registry uninstall keys (32-bit on 64-bit OS)
                try {
                    $uninstallPath32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                    if (Test-Path 'HKLM:\SOFTWARE\WOW6432Node' -ErrorAction SilentlyContinue) {
                        $software32 = Get-ItemProperty -Path $uninstallPath32 -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName } |
                            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString
                        if ($software32) {
                            $software32 | Export-Csv -Path (Join-Path $swDir 'installed_software_32bit.csv') -NoTypeInformation -Force -Encoding utf8
                            $catCopied++; $stats['FilesCopied']++
                            $stats['BytesCollected'] += (Get-Item (Join-Path $swDir 'installed_software_32bit.csv') -ErrorAction SilentlyContinue).Length
                        }
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-HotFix
                try {
                    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue
                    if ($hotfixes) {
                        $hotfixes | Select-Object HotFixID, Description, InstalledBy, InstalledOn |
                            Export-Csv -Path (Join-Path $swDir 'hotfixes.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $swDir 'hotfixes.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # WMIC product list (can be slow)
                    $saved = Save-CommandOutput -Name 'wmic_product' `
                        -ScriptBlock { Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue | Select-Object Name, Version, Vendor, InstallDate | Format-Table -AutoSize } `
                        -OutputFile (Join-Path $cmdDir 'wmic_product_list.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 13. WindowsDefender
            # =================================================================
            'WindowsDefender' {
                $defDir = Ensure-CollectionDir 'defender'

                # Get-MpComputerStatus
                try {
                    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($mpStatus) {
                        $mpStatus | Format-List |
                            Out-File -FilePath (Join-Path $defDir 'defender_status.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-MpPreference (includes exclusions)
                try {
                    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
                    if ($mpPref) {
                        $mpPref | Format-List |
                            Out-File -FilePath (Join-Path $defDir 'defender_preferences.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++

                        # Explicitly list exclusions for easy review
                        $exclusionLines = @(
                            "Windows Defender Exclusions"
                            "=" * 40
                            ""
                            "Excluded Paths:"
                        )
                        if ($mpPref.ExclusionPath) {
                            $mpPref.ExclusionPath | ForEach-Object { $exclusionLines += "  $_" }
                        } else { $exclusionLines += "  (none)" }
                        $exclusionLines += ""
                        $exclusionLines += "Excluded Processes:"
                        if ($mpPref.ExclusionProcess) {
                            $mpPref.ExclusionProcess | ForEach-Object { $exclusionLines += "  $_" }
                        } else { $exclusionLines += "  (none)" }
                        $exclusionLines += ""
                        $exclusionLines += "Excluded Extensions:"
                        if ($mpPref.ExclusionExtension) {
                            $mpPref.ExclusionExtension | ForEach-Object { $exclusionLines += "  $_" }
                        } else { $exclusionLines += "  (none)" }

                        $exclusionLines | Out-File -FilePath (Join-Path $defDir 'defender_exclusions.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-MpThreatDetection
                try {
                    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue
                    if ($threats) {
                        $threats | Format-List |
                            Out-File -FilePath (Join-Path $defDir 'defender_detections.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 14. RDPConfig
            # =================================================================
            'RDPConfig' {
                $regDir = Ensure-CollectionDir 'registry'
                $configDir = Ensure-CollectionDir 'config'

                # Terminal Services registry key
                $exported = Export-RegistryKey `
                    -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
                    -OutputFile (Join-Path $regDir 'terminal_server.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }

                # Terminal Services WinStations
                $exported = Export-RegistryKey `
                    -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                    -OutputFile (Join-Path $regDir 'rdp_tcp_config.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }

                # NLA setting
                $exported = Export-RegistryKey `
                    -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                    -OutputFile (Join-Path $configDir 'rdp_nla_config.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }

                # Recent RDP connections from HKCU
                $exported = Export-RegistryKey `
                    -KeyPath 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default' `
                    -OutputFile (Join-Path $regDir 'rdp_recent_connections.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }

                $exported = Export-RegistryKey `
                    -KeyPath 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers' `
                    -OutputFile (Join-Path $regDir 'rdp_saved_servers.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }
            }

            # =================================================================
            # 15. WMIPersistence
            # =================================================================
            'WMIPersistence' {
                $secDir = Ensure-CollectionDir 'security'

                # Event Filters
                try {
                    $filters = Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue
                    if ($filters) {
                        $filters | Format-List |
                            Out-File -FilePath (Join-Path $secDir 'wmi_event_filters.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Event Consumers
                try {
                    $consumers = Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue
                    if ($consumers) {
                        $consumers | Format-List |
                            Out-File -FilePath (Join-Path $secDir 'wmi_event_consumers.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Filter-to-Consumer Bindings
                try {
                    $bindings = Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue
                    if ($bindings) {
                        $bindings | Format-List |
                            Out-File -FilePath (Join-Path $secDir 'wmi_filter_bindings.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 16. Certificates
            # =================================================================
            'Certificates' {
                $secDir = Ensure-CollectionDir 'security'

                # LocalMachine Root certificates
                try {
                    $rootCerts = Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue
                    if ($rootCerts) {
                        $rootCerts | Select-Object Thumbprint, Subject, Issuer, NotBefore, NotAfter, HasPrivateKey |
                            Export-Csv -Path (Join-Path $secDir 'root_certificates.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $secDir 'root_certificates.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # LocalMachine CA certificates
                try {
                    $caCerts = Get-ChildItem -Path 'Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue
                    if ($caCerts) {
                        $caCerts | Select-Object Thumbprint, Subject, Issuer, NotBefore, NotAfter, HasPrivateKey |
                            Export-Csv -Path (Join-Path $secDir 'ca_certificates.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $secDir 'ca_certificates.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Check for certs with private keys (unusual for root/CA store)
                try {
                    $suspiciousCerts = @()
                    $suspiciousCerts += Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }
                    $suspiciousCerts += Get-ChildItem -Path 'Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }
                    if ($suspiciousCerts) {
                        $suspiciousCerts | Select-Object Thumbprint, Subject, Issuer, NotBefore, NotAfter, HasPrivateKey |
                            Export-Csv -Path (Join-Path $secDir 'suspicious_certs_with_private_keys.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 17. AutoStart
            # =================================================================
            'AutoStart' {
                $regDir    = Ensure-CollectionDir 'registry'
                $configDir = Ensure-CollectionDir 'config'

                # Common startup folder
                try {
                    $commonStartup = [System.Environment]::GetFolderPath('CommonStartup')
                    if ($commonStartup -and (Test-Path $commonStartup -ErrorAction SilentlyContinue)) {
                        $startupItems = Get-ChildItem -Path $commonStartup -ErrorAction SilentlyContinue
                        if ($startupItems) {
                            $lines = @("Common Startup Folder: $commonStartup", "=" * 60, "")
                            foreach ($item in $startupItems) {
                                $lines += "$($item.Name)  [$($item.LastWriteTime)]  $($item.Length) bytes"
                                # If it's a .lnk file, try to resolve target
                                if ($item.Extension -eq '.lnk') {
                                    try {
                                        $shell = New-Object -ComObject WScript.Shell
                                        $shortcut = $shell.CreateShortcut($item.FullName)
                                        $lines += "  Target: $($shortcut.TargetPath) $($shortcut.Arguments)"
                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                                    }
                                    catch { }
                                }
                            }
                            $lines | Out-File -FilePath (Join-Path $configDir 'startup_common.txt') -Force -Encoding utf8
                            $catCopied++; $stats['FilesCopied']++
                        }
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Current user startup folder
                try {
                    $userStartup = [System.Environment]::GetFolderPath('Startup')
                    if ($userStartup -and (Test-Path $userStartup -ErrorAction SilentlyContinue)) {
                        $startupItems = Get-ChildItem -Path $userStartup -ErrorAction SilentlyContinue
                        if ($startupItems) {
                            $lines = @("User Startup Folder: $userStartup", "=" * 60, "")
                            foreach ($item in $startupItems) {
                                $lines += "$($item.Name)  [$($item.LastWriteTime)]  $($item.Length) bytes"
                                if ($item.Extension -eq '.lnk') {
                                    try {
                                        $shell = New-Object -ComObject WScript.Shell
                                        $shortcut = $shell.CreateShortcut($item.FullName)
                                        $lines += "  Target: $($shortcut.TargetPath) $($shortcut.Arguments)"
                                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                                    }
                                    catch { }
                                }
                            }
                            $lines | Out-File -FilePath (Join-Path $configDir 'startup_user.txt') -Force -Encoding utf8
                            $catCopied++; $stats['FilesCopied']++
                        }
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # User profile startup folders (if CollectUserProfiles)
                if ($CollectUserProfiles) {
                    foreach ($profile in $userProfiles) {
                        $profileStartup = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
                        if (Test-Path $profileStartup -ErrorAction SilentlyContinue) {
                            try {
                                $items = Get-ChildItem -Path $profileStartup -ErrorAction SilentlyContinue
                                if ($items) {
                                    $safeName = $profile.Name -replace '[\\/:*?"<>|]', '_'
                                    $items | Format-Table -AutoSize -Property Name, LastWriteTime, Length |
                                        Out-File -FilePath (Join-Path $configDir "startup_user_$safeName.txt") -Force -Encoding utf8
                                    $catCopied++; $stats['FilesCopied']++
                                }
                            }
                            catch { }
                        }
                    }
                }
            }

            # =================================================================
            # 18. DLLSecurity
            # =================================================================
            'DLLSecurity' {
                $secDir = Ensure-CollectionDir 'security'
                $regDir = Ensure-CollectionDir 'registry'

                # Known DLLs
                $exported = Export-RegistryKey `
                    -KeyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' `
                    -OutputFile (Join-Path $regDir 'known_dlls.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }

                # PATH directories writability check
                try {
                    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -ne '' }
                    $pathLines = @("PATH Directory Writability Check", "=" * 50, "")
                    foreach ($dir in $pathDirs) {
                        if (Test-Path $dir -ErrorAction SilentlyContinue) {
                            $writable = $false
                            try {
                                $testFile = Join-Path $dir ".pwstest_$(Get-Random).tmp"
                                [System.IO.File]::Create($testFile).Close()
                                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                                $writable = $true
                            }
                            catch { $writable = $false }
                            $status = if ($writable) { "WRITABLE" } else { "read-only" }
                            $pathLines += "  [$status] $dir"
                        }
                        else {
                            $pathLines += "  [MISSING]  $dir"
                        }
                    }
                    $pathLines | Out-File -FilePath (Join-Path $secDir 'path_writability.txt') -Force -Encoding utf8
                    $catCopied++; $stats['FilesCopied']++
                }
                catch { $catErrors++; $stats['Errors']++ }

                # AppLocker policy
                try {
                    $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
                    if ($appLockerPolicy) {
                        $appLockerPolicy.RuleCollections | Format-List |
                            Out-File -FilePath (Join-Path $secDir 'applocker_policy.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $stats['Skipped']++ }

                # WDAC (Windows Defender Application Control) - CI policy
                $exported = Export-RegistryKey `
                    -KeyPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
                    -OutputFile (Join-Path $regDir 'wdac_deviceguard.txt')
                if ($exported) { $catCopied++; $stats['FilesCopied']++ }
                else { $stats['Skipped']++ }
            }

            # =================================================================
            # 19. BitLocker
            # =================================================================
            'BitLocker' {
                $secDir = Ensure-CollectionDir 'security'

                try {
                    $blVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
                    if ($blVolumes) {
                        $blVolumes | Format-List |
                            Out-File -FilePath (Join-Path $secDir 'bitlocker_status.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 20. SMBConfig
            # =================================================================
            'SMBConfig' {
                $configDir = Ensure-CollectionDir 'config'

                # SMB Server Configuration
                try {
                    $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                    if ($smbServer) {
                        $smbServer | Format-List |
                            Out-File -FilePath (Join-Path $configDir 'smb_server_config.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # SMB Client Configuration
                try {
                    $smbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
                    if ($smbClient) {
                        $smbClient | Format-List |
                            Out-File -FilePath (Join-Path $configDir 'smb_client_config.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # SMBv1 status check
                try {
                    $lines = @("SMBv1 Protocol Status", "=" * 40, "")

                    # Check via Get-WindowsOptionalFeature (client OS)
                    try {
                        $smbv1Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
                        if ($smbv1Feature) {
                            $lines += "SMB1Protocol Feature State: $($smbv1Feature.State)"
                        }
                    }
                    catch { }

                    # Check via registry
                    try {
                        $smbv1Reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -ErrorAction SilentlyContinue
                        if ($null -ne $smbv1Reg) {
                            $lines += "Registry SMB1 value: $($smbv1Reg.SMB1)"
                        }
                    }
                    catch { }

                    # Check via SmbServerConfiguration
                    try {
                        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                        if ($null -ne $smbConfig.EnableSMB1Protocol) {
                            $lines += "SmbServerConfiguration EnableSMB1Protocol: $($smbConfig.EnableSMB1Protocol)"
                        }
                    }
                    catch { }

                    $lines | Out-File -FilePath (Join-Path $configDir 'smbv1_status.txt') -Force -Encoding utf8
                    $catCopied++; $stats['FilesCopied']++
                }
                catch { $catErrors++; $stats['Errors']++ }
            }

            # =================================================================
            # 21. DNSCache
            # =================================================================
            'DNSCache' {
                $netDir = Ensure-CollectionDir 'network'
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Get-DnsClientCache
                try {
                    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
                    if ($dnsCache) {
                        $dnsCache | Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data |
                            Export-Csv -Path (Join-Path $netDir 'dns_cache.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $netDir 'dns_cache.csv') -ErrorAction SilentlyContinue).Length
                    }
                    else { $stats['Skipped']++ }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # ipconfig /displaydns
                    $saved = Save-CommandOutput -Name 'ipconfig_displaydns' -ScriptBlock { ipconfig /displaydns } `
                        -OutputFile (Join-Path $cmdDir 'ipconfig_displaydns.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }

            # =================================================================
            # 22. ProcessInfo
            # =================================================================
            'ProcessInfo' {
                $cmdDir = Ensure-CollectionDir 'collected_commands'

                # Get-Process
                try {
                    $procs = Get-Process -ErrorAction SilentlyContinue
                    if ($procs) {
                        $procs | Format-Table -AutoSize -Property Id, ProcessName, CPU, WorkingSet64, Path |
                            Out-File -FilePath (Join-Path $cmdDir 'get_process.txt') -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                # Get-CimInstance Win32_Process (includes CommandLine)
                try {
                    $cimProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
                    if ($cimProcs) {
                        $cimProcs | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId, CreationDate, SessionId |
                            Export-Csv -Path (Join-Path $cmdDir 'win32_process.csv') -NoTypeInformation -Force -Encoding utf8
                        $catCopied++; $stats['FilesCopied']++
                        $stats['BytesCollected'] += (Get-Item (Join-Path $cmdDir 'win32_process.csv') -ErrorAction SilentlyContinue).Length
                    }
                }
                catch { $catErrors++; $stats['Errors']++ }

                if (-not $SkipCommands) {
                    # tasklist /v
                    $saved = Save-CommandOutput -Name 'tasklist_v' -ScriptBlock { tasklist /v } `
                        -OutputFile (Join-Path $cmdDir 'tasklist_verbose.txt')
                    if ($saved) { $catCopied++ } else { $stats['Skipped']++ }
                }
            }
        }

        # --- Print category result ---
        if ($catErrors -gt 0) {
            Write-Host " $catCopied collected, $catErrors errors" -ForegroundColor Yellow
        }
        elseif ($catCopied -gt 0) {
            Write-Host " $catCopied collected" -ForegroundColor Green
        }
        else {
            Write-Host " nothing found" -ForegroundColor DarkGray
        }
    }

    # =========================================================================
    # Write collection manifest
    # =========================================================================
    $collectionEnd = Get-Date
    $duration = $collectionEnd - $collectionStart
    $manifestPath = Join-Path $OutputPath 'collection_manifest.txt'

    $manifest = @(
        "PWSPostProcessingSuite - Windows Artifact Collection Manifest"
        "=============================================================="
        "Collection Date : $collectionStart"
        "Hostname        : $env:COMPUTERNAME"
        "Collector       : Invoke-WindowsArtifactCollector (Active Mode)"
        "Duration        : $($duration.TotalSeconds.ToString('F1'))s"
        "OS Version      : $([System.Environment]::OSVersion.VersionString)"
        "PowerShell Ver  : $($PSVersionTable.PSVersion)"
        ""
        "Statistics:"
        "  Files Copied    : $($stats['FilesCopied'])"
        "  Commands Run    : $($stats['CommandsRun'])"
        "  Errors          : $($stats['Errors'])"
        "  Skipped (N/A)   : $($stats['Skipped'])"
        "  Bytes Collected : $([math]::Round($stats['BytesCollected'] / 1KB, 1)) KB"
        ""
        "Categories Collected:"
    )
    foreach ($catName in $categoriesToRun) {
        $manifest += "  - $catName : $($allCategories[$catName].Description)"
    }

    $manifest | Out-File -FilePath $manifestPath -Force -Encoding utf8

    # =========================================================================
    # Summary
    # =========================================================================
    Write-Host ""
    Write-Host "[+] Collection complete in $($duration.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
    Write-Host "    Files: $($stats['FilesCopied'])  Commands: $($stats['CommandsRun'])  Errors: $($stats['Errors'])  Skipped: $($stats['Skipped'])" -ForegroundColor White
    Write-Host "    Evidence stored: $OutputPath" -ForegroundColor White
    Write-Host ""

    return [PSCustomObject]@{
        PSTypeName      = 'PWSPostProcessingSuite.CollectionResult'
        OutputPath      = $OutputPath
        FilesCopied     = $stats['FilesCopied']
        CommandsRun     = $stats['CommandsRun']
        Errors          = $stats['Errors']
        Skipped         = $stats['Skipped']
        BytesCollected  = $stats['BytesCollected']
        Duration        = $duration
        CollectionStart = $collectionStart
        CollectionEnd   = $collectionEnd
        Categories      = @($categoriesToRun)
    }
}
