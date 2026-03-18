function Invoke-ContainerAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Docker/container artifacts for security issues and escape vectors.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check if we're analyzing a containerized system
    $dockerenvPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/.dockerenv'
    $cgroupPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc/1/cgroup'

    $isContainer = $false
    if (Test-Path $dockerenvPath) {
        $isContainer = $true
    }
    if (Test-Path $cgroupPath) {
        $cgroupContent = (Read-ArtifactContent -Path $cgroupPath) -join "`n"
        if ($cgroupContent -match 'docker|lxc|kubepods|containerd') {
            $isContainer = $true
        }
    }

    if ($isContainer) {
        $findings.Add((New-Finding -Id "CTR-001" -Severity "Informational" -Category "Container Security" `
            -Title "System is running inside a container" `
            -Description "Evidence indicates this system is a containerized environment (Docker/LXC/Kubernetes)." `
            -ArtifactPath "/.dockerenv" `
            -Evidence @("Container environment detected") `
            -Recommendation "Review container security configuration and escape vectors" `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    # Check Docker socket access
    $dockerSockPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/var/run/docker.sock'
    if (Test-Path $dockerSockPath) {
        $findings.Add((New-Finding -Id "CTR-002" -Severity "Critical" -Category "Container Security" `
            -Title "Docker socket accessible" `
            -Description "The Docker socket (/var/run/docker.sock) is accessible. If mounted inside a container, this allows full container escape by creating privileged containers." `
            -ArtifactPath "/var/run/docker.sock" `
            -Evidence @("Docker socket exists and is accessible") `
            -Recommendation "Do not mount the Docker socket into containers. Use Docker's rootless mode." `
            -MITRE "T1611" `
            -CVSSv3Score "9.9" `
            -TechnicalImpact "Accessible Docker socket allows full container escape by spawning privileged containers, granting root-level access to the host system."))
    }

    # Check Docker daemon configuration
    $dockerConfigPaths = @('/etc/docker/daemon.json', '/root/.docker/config.json')
    foreach ($configPath in $dockerConfigPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $configPath
        if (-not (Test-Path $resolved)) { continue }

        $content = (Read-ArtifactContent -Path $resolved) -join "`n"

        # Check for insecure registries
        if ($content -match '"insecure-registries"') {
            $findings.Add((New-Finding -Id "CTR-003" -Severity "Medium" -Category "Container Security" `
                -Title "Insecure Docker registries configured" `
                -Description "Docker daemon is configured to allow insecure (non-TLS) container registries." `
                -ArtifactPath $configPath `
                -Evidence @(($content | Select-String 'insecure-registries' -Context 0,3).Line) `
                -Recommendation "Use TLS for all container registries" `
                -MITRE "T1525" `
                -CVSSv3Score "5.9" `
                -TechnicalImpact "Insecure registries allow man-in-the-middle attacks to inject malicious container images, potentially compromising all services deployed from the registry."))
        }

        # Check for exposed Docker API
        if ($content -match '"hosts".*"tcp://' -or $content -match '0\.0\.0\.0:2375') {
            $findings.Add((New-Finding -Id "CTR-004" -Severity "Critical" -Category "Container Security" `
                -Title "Docker API exposed on network" `
                -Description "The Docker daemon API is exposed on a TCP port, potentially allowing remote container management without authentication." `
                -ArtifactPath $configPath `
                -Evidence @(($content | Select-String 'hosts|tcp://' -Context 0,1).Line) `
                -Recommendation "Remove TCP host binding. Use Docker socket or TLS-authenticated API only." `
                -MITRE "T1610" `
                -CVSSv3Score "9.8" `
                -TechnicalImpact "Unauthenticated Docker API exposure allows remote attackers to create, modify, and execute containers with full host access, leading to complete system compromise."))
        }
    }

    # Check Docker Compose files
    $composePaths = @()
    $composeFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter 'docker-compose*' -Recurse
    foreach ($f in $composeFiles) { $composePaths += $f }

    foreach ($composeFile in $composePaths) {
        $content = (Read-ArtifactContent -Path $composeFile.FullName) -join "`n"

        # Check for privileged containers
        if ($content -match 'privileged:\s*(true|yes)') {
            $findings.Add((New-Finding -Id "CTR-005" -Severity "Critical" -Category "Container Security" `
                -Title "Privileged container in docker-compose: $($composeFile.Name)" `
                -Description "A Docker Compose configuration defines a privileged container, which has full access to the host system." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @(($content -split "`n" | Select-String 'privileged' -Context 2,0).Line) `
                -Recommendation "Remove privileged mode. Use specific capabilities instead." `
                -MITRE "T1611" `
                -CVSSv3Score "9.0" `
                -TechnicalImpact "Privileged containers have unrestricted access to host devices and kernel capabilities, enabling trivial container escape and full host compromise."))
        }

        # Check for host network mode
        if ($content -match 'network_mode:\s*[''"]?host') {
            $findings.Add((New-Finding -Id "CTR-006" -Severity "High" -Category "Container Security" `
                -Title "Host network mode in docker-compose" `
                -Description "A container is using host network mode, sharing the host's network namespace." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @("network_mode: host") `
                -Recommendation "Use bridge or overlay networking instead of host mode" `
                -MITRE "T1611" `
                -CVSSv3Score "7.5" `
                -TechnicalImpact "Host network mode exposes all host network interfaces to the container, enabling network-based attacks on host services and other containers."))
        }

        # Check for host PID namespace
        if ($content -match 'pid:\s*[''"]?host') {
            $findings.Add((New-Finding -Id "CTR-007" -Severity "High" -Category "Container Security" `
                -Title "Host PID namespace in docker-compose" `
                -Description "A container shares the host's PID namespace, allowing it to see and interact with host processes." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @("pid: host") `
                -Recommendation "Remove host PID namespace sharing" `
                -MITRE "T1611" `
                -CVSSv3Score "7.5" `
                -TechnicalImpact "Host PID namespace sharing allows the container to view and interact with all host processes, enabling process injection and sensitive data extraction from host memory."))
        }

        # Check for cap_add: SYS_ADMIN
        if ($content -match 'SYS_ADMIN|SYS_PTRACE|NET_ADMIN|CAP_SYS_ADMIN') {
            $findings.Add((New-Finding -Id "CTR-008" -Severity "High" -Category "Container Security" `
                -Title "Dangerous capabilities added to container" `
                -Description "A container has been granted dangerous Linux capabilities that could enable container escape." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @(($content -split "`n" | Select-String 'SYS_ADMIN|SYS_PTRACE|NET_ADMIN' -Context 1,0).Line) `
                -Recommendation "Remove unnecessary capabilities. Apply principle of least privilege." `
                -MITRE "T1611" `
                -CVSSv3Score "8.2" `
                -TechnicalImpact "Dangerous Linux capabilities such as SYS_ADMIN or SYS_PTRACE can be exploited to escape the container, mount host filesystems, or inject code into host processes."))
        }

        # Check for Docker socket mount
        if ($content -match '/var/run/docker\.sock') {
            $findings.Add((New-Finding -Id "CTR-009" -Severity "Critical" -Category "Container Security" `
                -Title "Docker socket mounted into container" `
                -Description "The Docker socket is mounted into a container, enabling full control over the Docker daemon and container escape." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @("Volume: /var/run/docker.sock") `
                -Recommendation "Remove Docker socket mount. Use Docker API proxy with restricted permissions." `
                -MITRE "T1611" `
                -CVSSv3Score "9.9" `
                -TechnicalImpact "Docker socket mount inside a container provides full control over the Docker daemon, enabling container escape and root-level access to the host."))
        }
    }

    # ----------------------------------------------------------------
    # CTR-010: CVE-2019-5736 (runc vulnerability)
    # ----------------------------------------------------------------
    $runcVersionFiles = @()
    foreach ($pattern in @('runc*', 'docker_version*', 'container_runtime*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $runcVersionFiles += $f }
    }

    foreach ($vFile in $runcVersionFiles) {
        $content = (Read-ArtifactContent -Path $vFile.FullName) -join "`n"
        if ($content -match 'runc\s+version\s+(\d+\.\d+\.\d+)') {
            $runcVersion = $Matches[1]
            # CVE-2019-5736 affects runc < 1.0.0-rc6 (approximately < 1.0.0)
            $parts = $runcVersion.Split('.')
            $major = [int]$parts[0]; $minor = [int]$parts[1]
            if ($major -eq 0 -or ($major -eq 1 -and $minor -eq 0 -and $runcVersion -match 'rc[1-5]')) {
                $findings.Add((New-Finding -Id "CTR-010" -Severity "Critical" -Category "Container Security" `
                    -Title "CVE-2019-5736: Vulnerable runc version $runcVersion" `
                    -Description "The runc version ($runcVersion) is vulnerable to CVE-2019-5736, which allows container escape by overwriting the host runc binary." `
                    -ArtifactPath $vFile.FullName `
                    -Evidence @("runc version: $runcVersion", "CVE: CVE-2019-5736") `
                    -Recommendation "Upgrade runc to version 1.0.0-rc6 or later. Apply vendor patches." `
                    -MITRE "T1611" `
                    -CVSSv3Score "8.6" `
                    -TechnicalImpact "CVE-2019-5736 allows a container to overwrite the host runc binary, achieving container escape and root code execution on the host."))
            }
        }
    }

    # ----------------------------------------------------------------
    # CTR-011: Docker version CVE checks
    # ----------------------------------------------------------------
    foreach ($vFile in $runcVersionFiles) {
        $content = (Read-ArtifactContent -Path $vFile.FullName) -join "`n"
        if ($content -match 'Docker\s+version\s+(\d+\.\d+\.\d+)') {
            $dockerVersion = $Matches[1]
            $parts = $dockerVersion.Split('.')
            $major = [int]$parts[0]; $minor = [int]$parts[1]; $patch = [int]$parts[2]

            # CVE-2021-41091: Docker < 20.10.9
            if ($major -lt 20 -or ($major -eq 20 -and $minor -lt 10) -or ($major -eq 20 -and $minor -eq 10 -and $patch -lt 9)) {
                $findings.Add((New-Finding -Id "CTR-011" -Severity "Critical" -Category "Container Security" `
                    -Title "CVE-2021-41091: Vulnerable Docker version $dockerVersion" `
                    -Description "Docker version $dockerVersion is vulnerable to CVE-2021-41091, a directory traversal that allows unprivileged users to traverse and execute programs within the data directory." `
                    -ArtifactPath $vFile.FullName `
                    -Evidence @("Docker version: $dockerVersion", "CVE: CVE-2021-41091") `
                    -Recommendation "Upgrade Docker to version 20.10.9 or later." `
                    -MITRE "T1611" `
                    -CVSSv3Score "7.8" `
                    -TechnicalImpact "CVE-2021-41091 allows local unprivileged users to access container file systems and execute SUID binaries from within containers."))
            }
        }
    }

    # ----------------------------------------------------------------
    # CTR-013: Kubernetes service account token accessible (in container)
    # ----------------------------------------------------------------
    if ($isContainer) {
        $k8sTokenPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/var/run/secrets/kubernetes.io/serviceaccount/token'
        if (Test-Path $k8sTokenPath -PathType Leaf) {
            $findings.Add((New-Finding -Id "CTR-013" -Severity "High" -Category "Container Security" `
                -Title "Kubernetes service account token accessible inside container" `
                -Description "A Kubernetes service account token is mounted in this container at the default path. This token can be used to interact with the K8s API." `
                -ArtifactPath "/var/run/secrets/kubernetes.io/serviceaccount/token" `
                -Evidence @("Service account token found in container") `
                -Recommendation "Disable automatic mounting with automountServiceAccountToken: false. Apply RBAC policies to limit token permissions." `
                -MITRE "T1552.001" `
                -CVSSv3Score "7.5" `
                -TechnicalImpact "Kubernetes service account tokens inside containers can be exploited for lateral movement, secret access, and potential cluster compromise."))
        }
    }

    # ----------------------------------------------------------------
    # CTR-014: Container security profile (AppArmor/Seccomp) not applied
    # ----------------------------------------------------------------
    if ($isContainer) {
        $procStatus = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc/1/status'
        if (Test-Path $procStatus -PathType Leaf) {
            $statusContent = (Read-ArtifactContent -Path $procStatus) -join "`n"

            # Check Seccomp
            if ($statusContent -match 'Seccomp:\s*0') {
                $findings.Add((New-Finding -Id "CTR-014" -Severity "Medium" -Category "Container Security" `
                    -Title "Container running without Seccomp profile" `
                    -Description "The container's init process (PID 1) has Seccomp mode 0 (disabled). No syscall filtering is applied." `
                    -ArtifactPath "/proc/1/status" `
                    -Evidence @("Seccomp: 0 (disabled)") `
                    -Recommendation "Apply a Seccomp profile to restrict available syscalls. Use Docker's default Seccomp profile at minimum." `
                    -MITRE "T1611" `
                    -CVSSv3Score "5.3" `
                    -TechnicalImpact "Containers without Seccomp profiles can use all syscalls, increasing the kernel attack surface for container escape."))
            }
        }

        # Check for AppArmor
        $apparmorProc = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc/1/attr/current'
        if (Test-Path $apparmorProc -PathType Leaf) {
            $aaProfile = (Read-ArtifactContent -Path $apparmorProc) -join ''
            if ($aaProfile -match 'unconfined' -or [string]::IsNullOrWhiteSpace($aaProfile)) {
                $findings.Add((New-Finding -Id "CTR-014" -Severity "Medium" -Category "Container Security" `
                    -Title "Container running without AppArmor confinement" `
                    -Description "The container is running in AppArmor 'unconfined' mode, providing no mandatory access control restrictions." `
                    -ArtifactPath "/proc/1/attr/current" `
                    -Evidence @("AppArmor profile: unconfined") `
                    -Recommendation "Apply an AppArmor profile to the container. Use Docker's default AppArmor profile at minimum." `
                    -MITRE "T1611" `
                    -CVSSv3Score "5.3" `
                    -TechnicalImpact "Containers without AppArmor confinement have unrestricted file and process access, increasing the risk of container escape."))
            }
        }
    }

    # ----------------------------------------------------------------
    # CTR-015: Container with writable overlay filesystem
    # ----------------------------------------------------------------
    if ($isContainer) {
        $mountsPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc/1/mounts'
        if (-not (Test-Path $mountsPath)) {
            $mountsPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc/mounts'
        }

        if (Test-Path $mountsPath -PathType Leaf) {
            $mounts = Read-ArtifactContent -Path $mountsPath
            foreach ($mount in $mounts) {
                # Check for writable sensitive host mounts
                if ($mount -match 'overlay.*upperdir=(/var/lib/docker|/var/lib/containerd)' -and $mount -notmatch '\bro\b') {
                    $findings.Add((New-Finding -Id "CTR-015" -Severity "High" -Category "Container Security" `
                        -Title "Container overlay filesystem writable" `
                        -Description "The container's overlay filesystem has a writable upper directory in the Docker/containerd data path." `
                        -ArtifactPath "/proc/1/mounts" `
                        -Evidence @($mount.Trim()) `
                        -Recommendation "Use read-only root filesystem where possible (--read-only flag)." `
                        -MITRE "T1611" `
                        -CVSSv3Score "6.5" `
                        -TechnicalImpact "Writable overlay filesystem may allow modifications that persist across container restarts or affect other containers sharing the same image layers."))
                    break
                }
            }
        }
    }

    return $findings.ToArray()
}
