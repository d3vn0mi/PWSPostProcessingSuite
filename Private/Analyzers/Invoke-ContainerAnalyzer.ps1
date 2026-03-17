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
            -Recommendation "Review container security configuration and escape vectors"))
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
            -MITRE "T1611"))
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
                -MITRE "T1525"))
        }

        # Check for exposed Docker API
        if ($content -match '"hosts".*"tcp://' -or $content -match '0\.0\.0\.0:2375') {
            $findings.Add((New-Finding -Id "CTR-004" -Severity "Critical" -Category "Container Security" `
                -Title "Docker API exposed on network" `
                -Description "The Docker daemon API is exposed on a TCP port, potentially allowing remote container management without authentication." `
                -ArtifactPath $configPath `
                -Evidence @(($content | Select-String 'hosts|tcp://' -Context 0,1).Line) `
                -Recommendation "Remove TCP host binding. Use Docker socket or TLS-authenticated API only." `
                -MITRE "T1610"))
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
                -MITRE "T1611"))
        }

        # Check for host network mode
        if ($content -match 'network_mode:\s*[''"]?host') {
            $findings.Add((New-Finding -Id "CTR-006" -Severity "High" -Category "Container Security" `
                -Title "Host network mode in docker-compose" `
                -Description "A container is using host network mode, sharing the host's network namespace." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @("network_mode: host") `
                -Recommendation "Use bridge or overlay networking instead of host mode" `
                -MITRE "T1611"))
        }

        # Check for host PID namespace
        if ($content -match 'pid:\s*[''"]?host') {
            $findings.Add((New-Finding -Id "CTR-007" -Severity "High" -Category "Container Security" `
                -Title "Host PID namespace in docker-compose" `
                -Description "A container shares the host's PID namespace, allowing it to see and interact with host processes." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @("pid: host") `
                -Recommendation "Remove host PID namespace sharing" `
                -MITRE "T1611"))
        }

        # Check for cap_add: SYS_ADMIN
        if ($content -match 'SYS_ADMIN|SYS_PTRACE|NET_ADMIN|CAP_SYS_ADMIN') {
            $findings.Add((New-Finding -Id "CTR-008" -Severity "High" -Category "Container Security" `
                -Title "Dangerous capabilities added to container" `
                -Description "A container has been granted dangerous Linux capabilities that could enable container escape." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @(($content -split "`n" | Select-String 'SYS_ADMIN|SYS_PTRACE|NET_ADMIN' -Context 1,0).Line) `
                -Recommendation "Remove unnecessary capabilities. Apply principle of least privilege." `
                -MITRE "T1611"))
        }

        # Check for Docker socket mount
        if ($content -match '/var/run/docker\.sock') {
            $findings.Add((New-Finding -Id "CTR-009" -Severity "Critical" -Category "Container Security" `
                -Title "Docker socket mounted into container" `
                -Description "The Docker socket is mounted into a container, enabling full control over the Docker daemon and container escape." `
                -ArtifactPath $composeFile.FullName `
                -Evidence @("Volume: /var/run/docker.sock") `
                -Recommendation "Remove Docker socket mount. Use Docker API proxy with restricted permissions." `
                -MITRE "T1611"))
        }
    }

    return $findings.ToArray()
}
