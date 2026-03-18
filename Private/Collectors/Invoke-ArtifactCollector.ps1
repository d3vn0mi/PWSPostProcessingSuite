function Invoke-ArtifactCollector {
    <#
    .SYNOPSIS
        Collects forensic artifacts from a live Linux system into a filesystem-mirror structure.
    .DESCRIPTION
        Gathers configuration files, logs, runtime state, and command outputs from the
        local Linux system. Stores them in a mirror layout that the existing analyzers
        can process directly via Invoke-LinuxArtifactScan.
    .PARAMETER OutputPath
        Root directory where collected artifacts will be stored in filesystem-mirror layout.
    .PARAMETER IncludeCategories
        Collect only these categories. Default: all categories.
    .PARAMETER ExcludeCategories
        Skip these categories during collection.
    .PARAMETER SkipCommands
        Skip running live commands (only collect files). Useful for restricted environments.
    .PARAMETER MaxLogLines
        Maximum number of lines to collect from large log files. Default: 50000.
    .PARAMETER CollectTempDirs
        Include /tmp, /var/tmp, /dev/shm directory listings. Off by default (can be large).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string[]]$IncludeCategories,

        [string[]]$ExcludeCategories,

        [switch]$SkipCommands,

        [int]$MaxLogLines = 50000,

        [switch]$CollectTempDirs
    )

    $collectionStart = Get-Date
    $stats = @{ FilesCopied = 0; CommandsRun = 0; Errors = 0; Skipped = 0; BytesCollected = 0 }

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Artifact Collector - Live Evidence Gathering" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "[*] Output path: $OutputPath" -ForegroundColor White
    Write-Host "[*] Collection started: $collectionStart" -ForegroundColor White
    Write-Host ""

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # =========================================================================
    # Define all collection categories
    # =========================================================================
    $categories = [ordered]@{

        # -----------------------------------------------------------------
        # 1. User Accounts & Authentication
        # -----------------------------------------------------------------
        'UserAccounts' = @{
            Description = 'User accounts, groups, and authentication configuration'
            Files = @(
                '/etc/passwd'
                '/etc/shadow'
                '/etc/group'
                '/etc/gshadow'
                '/etc/login.defs'
                '/etc/security/limits.conf'
                '/etc/security/pam_env.conf'
                '/etc/security/capability.conf'
                '/etc/issue'
                '/etc/issue.net'
                '/etc/os-release'
                '/etc/lsb-release'
                '/etc/hostname'
            )
            Directories = @(
                @{ Path = '/etc/security/limits.d'; Filter = '*.conf' }
            )
            Commands = @(
                @{ Name = 'getent_passwd';  Command = 'getent passwd';  Output = 'collected_commands/getent_passwd.txt' }
                @{ Name = 'getent_group';   Command = 'getent group';   Output = 'collected_commands/getent_group.txt' }
                @{ Name = 'whoami';         Command = 'whoami';         Output = 'collected_commands/whoami.txt' }
                @{ Name = 'id';             Command = 'id';             Output = 'collected_commands/id.txt' }
                @{ Name = 'w';              Command = 'w';              Output = 'collected_commands/w.txt' }
                @{ Name = 'who';            Command = 'who';            Output = 'collected_commands/who.txt' }
                @{ Name = 'last';           Command = 'last -n 500';    Output = 'collected_commands/last.txt' }
                @{ Name = 'lastlog';        Command = 'lastlog';        Output = 'collected_commands/lastlog.txt' }
                @{ Name = 'uname';          Command = 'uname -a';       Output = 'collected_commands/uname.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 2. Sudoers & Privilege Escalation
        # -----------------------------------------------------------------
        'Sudoers' = @{
            Description = 'Sudoers configuration and privilege escalation'
            Files = @(
                '/etc/sudoers'
            )
            Directories = @(
                @{ Path = '/etc/sudoers.d'; Filter = '*' }
            )
            Commands = @()
        }

        # -----------------------------------------------------------------
        # 3. SSH Configuration & Keys
        # -----------------------------------------------------------------
        'SSH' = @{
            Description = 'SSH daemon configuration, host keys, and user SSH artifacts'
            Files = @(
                '/etc/ssh/sshd_config'
            )
            Directories = @(
                @{ Path = '/etc/ssh/sshd_config.d'; Filter = '*' }
                @{ Path = '/etc/ssh';               Filter = 'ssh_host_*' }
            )
            UserPaths = @(
                '.ssh/authorized_keys'
                '.ssh/authorized_keys2'
                '.ssh/known_hosts'
                '.ssh/config'
                '.ssh/id_rsa'
                '.ssh/id_rsa.pub'
                '.ssh/id_dsa'
                '.ssh/id_dsa.pub'
                '.ssh/id_ecdsa'
                '.ssh/id_ecdsa.pub'
                '.ssh/id_ed25519'
                '.ssh/id_ed25519.pub'
            )
            Commands = @()
        }

        # -----------------------------------------------------------------
        # 4. PAM Configuration
        # -----------------------------------------------------------------
        'PAM' = @{
            Description = 'Pluggable Authentication Module configuration'
            Files = @()
            Directories = @(
                @{ Path = '/etc/pam.d'; Filter = '*' }
            )
            Commands = @()
        }

        # -----------------------------------------------------------------
        # 5. Cron & Scheduled Tasks
        # -----------------------------------------------------------------
        'Cron' = @{
            Description = 'Cron jobs, at jobs, and scheduled tasks'
            Files = @(
                '/etc/crontab'
                '/etc/anacrontab'
                '/etc/incron.conf'
            )
            Directories = @(
                @{ Path = '/etc/cron.d';             Filter = '*' }
                @{ Path = '/etc/cron.daily';         Filter = '*' }
                @{ Path = '/etc/cron.hourly';        Filter = '*' }
                @{ Path = '/etc/cron.weekly';        Filter = '*' }
                @{ Path = '/etc/cron.monthly';       Filter = '*' }
                @{ Path = '/var/spool/cron/crontabs'; Filter = '*' }
                @{ Path = '/var/spool/cron';         Filter = '*' }
                @{ Path = '/var/spool/at';           Filter = '*' }
                @{ Path = '/var/spool/atjobs';       Filter = '*' }
                @{ Path = '/etc/incron.d';           Filter = '*' }
                @{ Path = '/var/spool/incron';       Filter = '*' }
            )
            Commands = @(
                @{ Name = 'crontab_root'; Command = 'crontab -l -u root 2>/dev/null || echo "[no crontab for root]"'; Output = 'collected_commands/crontab_root.txt' }
                @{ Name = 'systemctl_timers'; Command = 'systemctl list-timers --all --no-pager 2>/dev/null || true'; Output = 'collected_commands/systemctl_timers.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 6. Systemd Services & Init
        # -----------------------------------------------------------------
        'Systemd' = @{
            Description = 'Systemd service units, timers, sockets, and init scripts'
            Files = @()
            Directories = @(
                @{ Path = '/etc/systemd/system';       Filter = '*.service'; Recurse = $true }
                @{ Path = '/etc/systemd/system';       Filter = '*.timer';   Recurse = $true }
                @{ Path = '/etc/systemd/system';       Filter = '*.socket';  Recurse = $true }
                @{ Path = '/usr/lib/systemd/system';   Filter = '*.service' }
                @{ Path = '/usr/lib/systemd/system';   Filter = '*.timer' }
                @{ Path = '/lib/systemd/system';       Filter = '*.service' }
                @{ Path = '/lib/systemd/system';       Filter = '*.timer' }
                @{ Path = '/run/systemd/system';       Filter = '*.service' }
                @{ Path = '/run/systemd/system';       Filter = '*.timer' }
                @{ Path = '/etc/init.d';               Filter = '*' }
            )
            UserPaths = @(
                '.config/systemd/user/*.service'
                '.config/systemd/user/*.timer'
            )
            Commands = @(
                @{ Name = 'systemctl_units';    Command = 'systemctl list-unit-files --no-pager 2>/dev/null || true';  Output = 'collected_commands/systemctl_unit_files.txt' }
                @{ Name = 'systemctl_services'; Command = 'systemctl list-units --type=service --all --no-pager 2>/dev/null || true'; Output = 'collected_commands/systemctl_services.txt' }
                @{ Name = 'systemctl_failed';   Command = 'systemctl --failed --no-pager 2>/dev/null || true';         Output = 'collected_commands/systemctl_failed.txt' }
                @{ Name = 'runlevel';           Command = 'runlevel 2>/dev/null || who -r 2>/dev/null || true';        Output = 'collected_commands/runlevel.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 7. Shell Profiles (system & user)
        # -----------------------------------------------------------------
        'ShellProfiles' = @{
            Description = 'System and user shell profile/rc files'
            Files = @(
                '/etc/profile'
                '/etc/bash.bashrc'
                '/etc/bashrc'
                '/etc/environment'
            )
            Directories = @(
                @{ Path = '/etc/profile.d';  Filter = '*' }
                @{ Path = '/etc/default';    Filter = '*' }
            )
            UserPaths = @(
                '.bashrc'
                '.bash_profile'
                '.profile'
                '.bash_login'
                '.bash_logout'
                '.zshrc'
                '.zprofile'
                '.zlogin'
            )
            Commands = @(
                @{ Name = 'env'; Command = 'env'; Output = 'collected_commands/env.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 8. Shell History
        # -----------------------------------------------------------------
        'ShellHistory' = @{
            Description = 'Shell command history for all users'
            Files = @()
            Directories = @()
            UserPaths = @(
                '.bash_history'
                '.zsh_history'
                '.mysql_history'
                '.psql_history'
                '.python_history'
            )
            Commands = @()
        }

        # -----------------------------------------------------------------
        # 9. Sysctl & Kernel Configuration
        # -----------------------------------------------------------------
        'Sysctl' = @{
            Description = 'Kernel parameters and sysctl configuration'
            Files = @(
                '/etc/sysctl.conf'
            )
            Directories = @(
                @{ Path = '/etc/sysctl.d'; Filter = '*.conf' }
            )
            Commands = @(
                @{ Name = 'sysctl_all'; Command = 'sysctl -a 2>/dev/null || true'; Output = 'collected_commands/sysctl_all.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 10. Filesystem Configuration
        # -----------------------------------------------------------------
        'Filesystem' = @{
            Description = 'Filesystem mounts, SUID/SGID binaries, and permissions'
            Files = @(
                '/etc/fstab'
            )
            Directories = @()
            Commands = @(
                @{ Name = 'mount';      Command = 'mount';                                  Output = 'collected_commands/mount.txt' }
                @{ Name = 'df';         Command = 'df -h';                                  Output = 'collected_commands/df.txt' }
                @{ Name = 'proc_mounts'; Command = 'cat /proc/mounts';                      Output = 'proc/mounts' }
                @{ Name = 'suid_bins';  Command = 'find / -perm -4000 -type f 2>/dev/null | head -500'; Output = 'collected_commands/suid_binaries.txt' }
                @{ Name = 'sgid_bins';  Command = 'find / -perm -2000 -type f 2>/dev/null | head -500'; Output = 'collected_commands/sgid_binaries.txt' }
                @{ Name = 'world_writable'; Command = 'find /etc /usr /var -perm -o+w -type f 2>/dev/null | head -500'; Output = 'collected_commands/world_writable.txt' }
                @{ Name = 'capabilities'; Command = 'getcap -r / 2>/dev/null | head -500';  Output = 'collected_commands/file_capabilities.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 11. Network Configuration
        # -----------------------------------------------------------------
        'Network' = @{
            Description = 'Network interfaces, routing, DNS, and host configuration'
            Files = @(
                '/etc/hosts'
                '/etc/hosts.allow'
                '/etc/hosts.deny'
                '/etc/hosts.equiv'
                '/etc/resolv.conf'
                '/etc/network/interfaces'
                '/etc/nsswitch.conf'
            )
            Directories = @(
                @{ Path = '/etc/network/interfaces.d'; Filter = '*' }
                @{ Path = '/etc/netplan';              Filter = '*.yaml' }
                @{ Path = '/etc/sysconfig/network-scripts'; Filter = 'ifcfg-*' }
            )
            Commands = @(
                @{ Name = 'ip_addr';   Command = 'ip addr 2>/dev/null || ifconfig -a 2>/dev/null || true';  Output = 'collected_commands/ip_addr.txt' }
                @{ Name = 'ip_route';  Command = 'ip route 2>/dev/null || route -n 2>/dev/null || true';    Output = 'collected_commands/ip_route.txt' }
                @{ Name = 'ip_link';   Command = 'ip link 2>/dev/null || true';                             Output = 'collected_commands/ip_link.txt' }
                @{ Name = 'hostname';  Command = 'hostname -f 2>/dev/null || hostname 2>/dev/null || true'; Output = 'collected_commands/hostname.txt' }
                @{ Name = 'arp';       Command = 'ip neigh 2>/dev/null || arp -an 2>/dev/null || true';     Output = 'collected_commands/arp.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 12. Firewall
        # -----------------------------------------------------------------
        'Firewall' = @{
            Description = 'Firewall rules and configuration'
            Files = @(
                '/etc/iptables/rules.v4'
                '/etc/iptables/rules.v6'
                '/etc/sysconfig/iptables'
                '/etc/iptables.rules'
                '/etc/ufw/ufw.conf'
                '/etc/ufw/before.rules'
                '/etc/ufw/after.rules'
            )
            Directories = @()
            Commands = @(
                @{ Name = 'iptables';      Command = 'iptables -L -n -v 2>/dev/null || true';          Output = 'collected_commands/iptables.txt' }
                @{ Name = 'iptables_nat';  Command = 'iptables -L -n -v -t nat 2>/dev/null || true';   Output = 'collected_commands/iptables_nat.txt' }
                @{ Name = 'ip6tables';     Command = 'ip6tables -L -n -v 2>/dev/null || true';         Output = 'collected_commands/ip6tables.txt' }
                @{ Name = 'ufw_status';    Command = 'ufw status verbose 2>/dev/null || true';         Output = 'collected_commands/ufw_status.txt' }
                @{ Name = 'nft_list';      Command = 'nft list ruleset 2>/dev/null || true';           Output = 'collected_commands/nft_ruleset.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 13. Web Servers
        # -----------------------------------------------------------------
        'WebServer' = @{
            Description = 'Web server configuration (Apache, Nginx)'
            Files = @(
                '/etc/nginx/nginx.conf'
                '/etc/apache2/apache2.conf'
                '/etc/httpd/conf/httpd.conf'
            )
            Directories = @(
                @{ Path = '/etc/nginx/conf.d';            Filter = '*.conf' }
                @{ Path = '/etc/nginx/sites-available';   Filter = '*' }
                @{ Path = '/etc/nginx/sites-enabled';     Filter = '*' }
                @{ Path = '/etc/apache2/conf-available';  Filter = '*.conf' }
                @{ Path = '/etc/apache2/conf-enabled';    Filter = '*.conf' }
                @{ Path = '/etc/apache2/mods-enabled';    Filter = '*.conf' }
                @{ Path = '/etc/apache2/sites-available'; Filter = '*' }
                @{ Path = '/etc/apache2/sites-enabled';   Filter = '*' }
                @{ Path = '/etc/httpd/conf.d';            Filter = '*.conf' }
            )
            Commands = @(
                @{ Name = 'apache_v'; Command = 'apache2 -v 2>/dev/null || httpd -v 2>/dev/null || true'; Output = 'collected_commands/apache_version.txt' }
                @{ Name = 'nginx_v';  Command = 'nginx -v 2>&1 || true';                                  Output = 'collected_commands/nginx_version.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 14. Auth / Syslog / Audit / Package Logs
        # -----------------------------------------------------------------
        'Logs' = @{
            Description = 'System logs (auth, syslog, audit, package, cloud-init)'
            Files = @(
                '/var/log/auth.log'
                '/var/log/auth.log.1'
                '/var/log/secure'
                '/var/log/secure.1'
                '/var/log/syslog'
                '/var/log/syslog.1'
                '/var/log/messages'
                '/var/log/messages.1'
                '/var/log/kern.log'
                '/var/log/kern.log.1'
                '/var/log/audit/audit.log'
                '/var/log/audit/audit.log.1'
                '/var/log/dpkg.log'
                '/var/log/dpkg.log.1'
                '/var/log/yum.log'
                '/var/log/dnf.log'
                '/var/log/apt/history.log'
                '/var/log/apt/term.log'
                '/var/log/cloud-init.log'
                '/var/log/cloud-init-output.log'
                '/var/log/wtmp'
                '/var/log/btmp'
                '/var/log/faillog'
                '/var/log/lastlog'
            )
            Directories = @()
            Commands = @(
                @{ Name = 'log_listing'; Command = 'ls -la /var/log/ 2>/dev/null || true'; Output = 'collected_commands/var_log_listing.txt' }
                @{ Name = 'journal_boot'; Command = 'journalctl -b --no-pager -n 5000 2>/dev/null || true'; Output = 'collected_commands/journalctl_boot.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 15. Kernel Modules
        # -----------------------------------------------------------------
        'KernelModules' = @{
            Description = 'Loaded kernel modules and module configuration'
            Files = @(
                '/etc/modules'
                '/proc/modules'
            )
            Directories = @(
                @{ Path = '/etc/modprobe.d'; Filter = '*.conf' }
            )
            Commands = @(
                @{ Name = 'lsmod'; Command = 'lsmod'; Output = 'collected_commands/lsmod.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 16. LD Preload & Library Loading
        # -----------------------------------------------------------------
        'LDPreload' = @{
            Description = 'Dynamic linker preload and library configuration'
            Files = @(
                '/etc/ld.so.preload'
                '/etc/ld.so.conf'
            )
            Directories = @(
                @{ Path = '/etc/ld.so.conf.d'; Filter = '*.conf' }
            )
            Commands = @(
                @{ Name = 'ldconfig'; Command = 'ldconfig -p 2>/dev/null | head -200 || true'; Output = 'collected_commands/ldconfig.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 17. Process & Runtime State
        # -----------------------------------------------------------------
        'Process' = @{
            Description = 'Running processes, open files, and runtime state'
            Files = @(
                '/proc/1/cgroup'
                '/proc/1/status'
                '/proc/cmdline'
                '/proc/meminfo'
                '/proc/version'
            )
            Directories = @()
            Commands = @(
                @{ Name = 'ps_aux';     Command = 'ps auxww';                                        Output = 'collected_commands/ps_aux.txt' }
                @{ Name = 'ps_tree';    Command = 'ps axjf 2>/dev/null || ps aux --forest 2>/dev/null || true'; Output = 'collected_commands/ps_tree.txt' }
                @{ Name = 'lsof_net';   Command = 'lsof -i -n -P 2>/dev/null | head -500 || true';   Output = 'collected_commands/lsof_network.txt' }
                @{ Name = 'proc_deleted'; Command = 'ls -la /proc/*/exe 2>/dev/null | grep deleted | head -100 || true'; Output = 'collected_commands/proc_deleted_exe.txt' }
                @{ Name = 'proc_environ'; Command = 'for p in /proc/[0-9]*/environ; do pid=$(echo $p | cut -d/ -f3); echo "=== PID $pid ==="; cat "$p" 2>/dev/null | tr "\0" "\n"; echo; done 2>/dev/null | head -5000 || true'; Output = 'collected_commands/proc_environ.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 18. Sockets & Listening Services
        # -----------------------------------------------------------------
        'Sockets' = @{
            Description = 'Listening sockets, established connections, and Unix sockets'
            Files = @(
                '/proc/net/tcp'
                '/proc/net/tcp6'
                '/proc/net/udp'
                '/proc/net/udp6'
                '/proc/net/unix'
            )
            Directories = @()
            Commands = @(
                @{ Name = 'ss_listen';   Command = 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true';   Output = 'collected_commands/ss_listen.txt' }
                @{ Name = 'ss_all';      Command = 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true';  Output = 'collected_commands/ss_all.txt' }
                @{ Name = 'ss_summary';  Command = 'ss -s 2>/dev/null || true';                                    Output = 'collected_commands/ss_summary.txt' }
                @{ Name = 'ss_unix';     Command = 'ss -xlp 2>/dev/null | head -200 || true';                      Output = 'collected_commands/ss_unix.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 19. Container & Docker
        # -----------------------------------------------------------------
        'Container' = @{
            Description = 'Docker, Kubernetes, and container runtime artifacts'
            Files = @(
                '/etc/docker/daemon.json'
                '/.dockerenv'
                '/proc/1/cgroup'
            )
            Directories = @(
                @{ Path = '/etc/kubernetes'; Filter = '*'; Recurse = $true }
            )
            UserPaths = @(
                '.docker/config.json'
                '.kube/config'
            )
            Commands = @(
                @{ Name = 'docker_ps';     Command = 'docker ps -a 2>/dev/null || true';     Output = 'collected_commands/docker_ps.txt' }
                @{ Name = 'docker_images'; Command = 'docker images 2>/dev/null || true';     Output = 'collected_commands/docker_images.txt' }
                @{ Name = 'docker_info';   Command = 'docker info 2>/dev/null || true';       Output = 'collected_commands/docker_info.txt' }
                @{ Name = 'cgroup_check';  Command = 'cat /proc/1/cgroup 2>/dev/null || true'; Output = 'collected_commands/cgroup_self.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 20. Cloud Security
        # -----------------------------------------------------------------
        'Cloud' = @{
            Description = 'Cloud provider credentials and configuration'
            Files = @(
                '/etc/boto.cfg'
                '/var/lib/cloud/instance/user-data.txt'
                '/var/lib/cloud/instance/vendor-data.txt'
                '/run/cloud-init/instance-data.json'
            )
            Directories = @()
            UserPaths = @(
                '.aws/credentials'
                '.aws/config'
                '.boto'
                '.s3cfg'
                '.azure/accessTokens.json'
                '.azure/azureProfile.json'
                '.config/gcloud/credentials.db'
                '.config/gcloud/properties'
                '.config/gcloud/application_default_credentials.json'
            )
            Commands = @(
                @{ Name = 'cloud_meta_aws'; Command = 'curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null || echo "[not available]"'; Output = 'collected_commands/cloud_metadata_aws.txt' }
                @{ Name = 'cloud_meta_gcp'; Command = 'curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null || echo "[not available]"'; Output = 'collected_commands/cloud_metadata_gcp.txt' }
                @{ Name = 'cloud_meta_azure'; Command = 'curl -s --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || echo "[not available]"'; Output = 'collected_commands/cloud_metadata_azure.txt' }
            )
        }

        # -----------------------------------------------------------------
        # 21. Credential Scanning Artifacts
        # -----------------------------------------------------------------
        'Credentials' = @{
            Description = 'Configuration files that may contain credentials'
            Files = @()
            Directories = @(
                @{ Path = '/etc/mysql';      Filter = '*.cnf';  Recurse = $true }
                @{ Path = '/etc/postgresql';  Filter = '*.conf'; Recurse = $true }
                @{ Path = '/etc/redis';       Filter = '*.conf' }
            )
            UserPaths = @(
                '.my.cnf'
                '.pgpass'
                '.netrc'
                '.git-credentials'
            )
            Commands = @()
        }

        # -----------------------------------------------------------------
        # 22. D-Bus & R-Commands (legacy)
        # -----------------------------------------------------------------
        'Misc' = @{
            Description = 'D-Bus configuration, legacy r-commands, and miscellaneous'
            Files = @(
                '/etc/xinetd.d/rsh'
                '/etc/xinetd.d/rlogin'
                '/etc/xinetd.d/rexec'
            )
            Directories = @(
                @{ Path = '/etc/dbus-1/system.d';  Filter = '*.conf' }
            )
            UserPaths = @(
                '.rhosts'
            )
            Commands = @(
                @{ Name = 'packages_dpkg'; Command = 'dpkg -l 2>/dev/null | tail -n +6 || true'; Output = 'collected_commands/dpkg_list.txt' }
                @{ Name = 'packages_rpm';  Command = 'rpm -qa 2>/dev/null || true';               Output = 'collected_commands/rpm_list.txt' }
            )
        }
    }

    # =========================================================================
    # Filter categories
    # =========================================================================
    $categoriesToRun = $categories.Keys | ForEach-Object { $_ }
    if ($IncludeCategories) {
        $categoriesToRun = $categoriesToRun | Where-Object { $_ -in $IncludeCategories }
    }
    if ($ExcludeCategories) {
        $categoriesToRun = $categoriesToRun | Where-Object { $_ -notin $ExcludeCategories }
    }

    Write-Host "[*] Collecting $($categoriesToRun.Count) categories..." -ForegroundColor White
    Write-Host ""

    # =========================================================================
    # Discover user home directories
    # =========================================================================
    $userHomes = @()
    if (Test-Path '/etc/passwd') {
        $passwdContent = Get-Content '/etc/passwd' -ErrorAction SilentlyContinue
        foreach ($line in $passwdContent) {
            if ($line -match '^#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $fields = $line.Split(':')
            if ($fields.Count -ge 6) {
                $homeDir = $fields[5]
                $shell = if ($fields.Count -ge 7) { $fields[6] } else { '' }
                # Collect from users with real home dirs (not /nonexistent, /dev/null, etc.)
                if ($homeDir -and (Test-Path $homeDir) -and $homeDir -notmatch '^/(dev|proc|sys|nonexistent)') {
                    $userHomes += $homeDir
                }
            }
        }
    }
    else {
        # Fallback: check /home/* and /root
        if (Test-Path '/root') { $userHomes += '/root' }
        $homeEntries = Get-ChildItem '/home' -Directory -ErrorAction SilentlyContinue
        foreach ($h in $homeEntries) { $userHomes += $h.FullName }
    }
    $userHomes = $userHomes | Select-Object -Unique
    Write-Host "[*] Found $($userHomes.Count) user home directories" -ForegroundColor White

    # =========================================================================
    # Helper: Copy a single file into the mirror structure
    # =========================================================================
    function Copy-ArtifactFile {
        param(
            [string]$SourcePath,
            [string]$DestRoot,
            [int]$MaxLines = 0
        )

        if (-not (Test-Path $SourcePath -ErrorAction SilentlyContinue)) {
            return $false
        }

        # Build mirror destination
        $relativePath = $SourcePath.TrimStart('/')
        $destPath = Join-Path $DestRoot $relativePath
        $destDir = Split-Path $destPath -Parent

        try {
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }

            # For binary files (wtmp, btmp, lastlog), just copy
            $binaryFiles = @('wtmp', 'btmp', 'lastlog', 'faillog')
            $fileName = Split-Path $SourcePath -Leaf
            if ($fileName -in $binaryFiles) {
                Copy-Item -Path $SourcePath -Destination $destPath -Force -ErrorAction Stop
            }
            elseif ($MaxLines -gt 0) {
                # Tail large log files to keep collection manageable
                $content = Get-Content -Path $SourcePath -Tail $MaxLines -ErrorAction Stop
                Set-Content -Path $destPath -Value $content -Force -ErrorAction Stop
            }
            else {
                Copy-Item -Path $SourcePath -Destination $destPath -Force -ErrorAction Stop
            }

            $stats['BytesCollected'] += (Get-Item $destPath -ErrorAction SilentlyContinue).Length
            return $true
        }
        catch {
            # Permission denied is expected for some files (shadow, etc.)
            Write-Verbose "  Could not copy $SourcePath : $_"
            return $false
        }
    }

    # =========================================================================
    # Process each category
    # =========================================================================
    foreach ($catName in $categoriesToRun) {
        $cat = $categories[$catName]
        Write-Host "  [>] $catName - $($cat.Description)..." -ForegroundColor DarkGray -NoNewline

        $catCopied = 0
        $catErrors = 0

        # --- Collect individual files ---
        if ($cat.Files) {
            foreach ($filePath in $cat.Files) {
                if (Test-Path $filePath -ErrorAction SilentlyContinue) {
                    # Apply line limit to log files
                    $lineLimit = 0
                    if ($filePath -match '/var/log/') { $lineLimit = $MaxLogLines }

                    $copied = Copy-ArtifactFile -SourcePath $filePath -DestRoot $OutputPath -MaxLines $lineLimit
                    if ($copied) {
                        $catCopied++
                        $stats['FilesCopied']++
                    }
                    else {
                        $catErrors++
                        $stats['Errors']++
                    }
                }
                else {
                    $stats['Skipped']++
                }
            }
        }

        # --- Collect directories ---
        if ($cat.Directories) {
            foreach ($dirSpec in $cat.Directories) {
                $dirPath = $dirSpec.Path
                $filter = $dirSpec.Filter
                $recurse = if ($dirSpec.ContainsKey('Recurse')) { $dirSpec.Recurse } else { $false }

                if (Test-Path $dirPath -ErrorAction SilentlyContinue) {
                    $gciParams = @{
                        Path        = $dirPath
                        Filter      = $filter
                        File        = $true
                        ErrorAction = 'SilentlyContinue'
                    }
                    if ($recurse) { $gciParams['Recurse'] = $true }

                    $files = Get-ChildItem @gciParams
                    foreach ($file in $files) {
                        $copied = Copy-ArtifactFile -SourcePath $file.FullName -DestRoot $OutputPath
                        if ($copied) {
                            $catCopied++
                            $stats['FilesCopied']++
                        }
                        else {
                            $catErrors++
                            $stats['Errors']++
                        }
                    }
                }
                else {
                    $stats['Skipped']++
                }
            }
        }

        # --- Collect user-specific paths ---
        if ($cat.UserPaths) {
            foreach ($home in $userHomes) {
                foreach ($userFile in $cat.UserPaths) {
                    # Handle glob patterns in user paths
                    if ($userFile -match '\*') {
                        $userDir = Join-Path $home (Split-Path $userFile -Parent)
                        $userFilter = Split-Path $userFile -Leaf
                        if (Test-Path $userDir -ErrorAction SilentlyContinue) {
                            $matchedFiles = Get-ChildItem -Path $userDir -Filter $userFilter -File -ErrorAction SilentlyContinue
                            foreach ($mf in $matchedFiles) {
                                $copied = Copy-ArtifactFile -SourcePath $mf.FullName -DestRoot $OutputPath
                                if ($copied) {
                                    $catCopied++
                                    $stats['FilesCopied']++
                                }
                            }
                        }
                    }
                    else {
                        $fullPath = Join-Path $home $userFile
                        if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                            $copied = Copy-ArtifactFile -SourcePath $fullPath -DestRoot $OutputPath
                            if ($copied) {
                                $catCopied++
                                $stats['FilesCopied']++
                            }
                            else {
                                $catErrors++
                                $stats['Errors']++
                            }
                        }
                    }
                }
            }
        }

        # --- Run commands ---
        if ($cat.Commands -and -not $SkipCommands) {
            foreach ($cmdSpec in $cat.Commands) {
                $cmdOutput = $cmdSpec.Output
                $cmdString = $cmdSpec.Command
                $destFile = Join-Path $OutputPath $cmdOutput
                $destDir = Split-Path $destFile -Parent

                try {
                    if (-not (Test-Path $destDir)) {
                        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                    }

                    $result = bash -c $cmdString 2>&1
                    if ($null -ne $result) {
                        $result | Out-File -FilePath $destFile -Force -Encoding utf8
                        $stats['CommandsRun']++
                        $catCopied++
                    }
                }
                catch {
                    Write-Verbose "  Command failed ($($cmdSpec.Name)): $_"
                    $catErrors++
                    $stats['Errors']++
                }
            }
        }

        # --- Optional: temp directory listings ---
        if ($catName -eq 'Filesystem' -and $CollectTempDirs) {
            $tempDirs = @('/tmp', '/var/tmp', '/dev/shm')
            foreach ($td in $tempDirs) {
                if (Test-Path $td) {
                    $listFile = Join-Path $OutputPath "collected_commands/$($td.Replace('/', '_').TrimStart('_'))_listing.txt"
                    $listDir = Split-Path $listFile -Parent
                    if (-not (Test-Path $listDir)) {
                        New-Item -ItemType Directory -Path $listDir -Force | Out-Null
                    }
                    try {
                        $listing = bash -c "ls -laR '$td' 2>/dev/null | head -2000" 2>&1
                        $listing | Out-File -FilePath $listFile -Force -Encoding utf8
                        $stats['CommandsRun']++
                    }
                    catch { }
                }
            }
        }

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
        "PWSPostProcessingSuite - Artifact Collection Manifest"
        "======================================================"
        "Collection Date : $collectionStart"
        "Hostname        : $(hostname 2>/dev/null)"
        "Collector       : Invoke-ArtifactCollector (Active Mode)"
        "Duration        : $($duration.TotalSeconds.ToString('F1'))s"
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
        $manifest += "  - $catName : $($categories[$catName].Description)"
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
