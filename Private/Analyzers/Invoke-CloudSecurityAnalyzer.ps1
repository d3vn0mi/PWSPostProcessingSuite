function Invoke-CloudSecurityAnalyzer {
    <#
    .SYNOPSIS
        Analyzes collected artifacts for cloud environment indicators and misconfigurations.
    .DESCRIPTION
        Inspired by LinPEAS cloud enumeration sections. Detects AWS/GCP/Azure/Kubernetes
        credentials, cloud metadata indicators, and cloud VM presence from collected artifacts.
    .PARAMETER EvidencePath
        Root folder path containing collected Linux artifacts.
    .PARAMETER Rules
        Hashtable of detection rules from the rules engine.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerCategory = 'Cloud Security'
    $cloudDetected = $false

    # ----------------------------------------------------------------
    # CLOUD-001: AWS credentials and configuration
    # ----------------------------------------------------------------
    $awsPaths = @(
        @{ Linux = '/root/.aws/credentials'; Desc = 'root AWS credentials' }
        @{ Linux = '/root/.aws/config'; Desc = 'root AWS config' }
        @{ Linux = '/etc/boto.cfg'; Desc = 'Boto configuration' }
        @{ Linux = '/root/.boto'; Desc = 'root Boto config' }
        @{ Linux = '/root/.s3cfg'; Desc = 'S3cmd configuration' }
    )

    # Also check all home directories
    $homeDir = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/home'
    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            $awsPaths += @{ Linux = "/home/$($userDir.Name)/.aws/credentials"; Desc = "$($userDir.Name) AWS credentials" }
            $awsPaths += @{ Linux = "/home/$($userDir.Name)/.aws/config"; Desc = "$($userDir.Name) AWS config" }
            $awsPaths += @{ Linux = "/home/$($userDir.Name)/.boto"; Desc = "$($userDir.Name) Boto config" }
            $awsPaths += @{ Linux = "/home/$($userDir.Name)/.s3cfg"; Desc = "$($userDir.Name) S3cmd config" }
        }
    }

    foreach ($awsPath in $awsPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $awsPath.Linux
        if (-not (Test-Path $resolved -PathType Leaf)) { continue }

        $cloudDetected = $true
        $content = (Read-ArtifactContent -Path $resolved) -join "`n"

        $severity = 'Medium'
        $evidence = @("File: $($awsPath.Linux)", "Description: $($awsPath.Desc)")

        # Check if the file contains actual credentials
        if ($content -match 'aws_access_key_id\s*=' -or $content -match 'aws_secret_access_key\s*=') {
            $severity = 'High'
            $evidence += "Contains AWS access key ID and/or secret access key"
        }
        if ($content -match 'aws_session_token\s*=') {
            $evidence += "Contains AWS session token (temporary credentials)"
        }

        $findings.Add((New-Finding -Id 'CLOUD-001' -Severity $severity -Category $analyzerCategory `
            -Title "AWS credential file found: $($awsPath.Desc)" `
            -Description "AWS credential or configuration file detected at $($awsPath.Linux). These files may contain access keys that grant access to AWS services." `
            -ArtifactPath $resolved `
            -Evidence $evidence `
            -Recommendation "Verify AWS credentials are rotated regularly. Use IAM roles instead of static access keys where possible. Check for overly permissive IAM policies." `
            -MITRE 'T1552.001' `
            -CVSSv3Score $(if ($severity -eq 'High') { '8.1' } else { '5.3' }) `
            -TechnicalImpact "AWS credential files may allow attackers to access cloud resources, create/modify infrastructure, access S3 data, or escalate privileges in the cloud environment."))
    }

    # ----------------------------------------------------------------
    # CLOUD-002: GCP service account keys
    # ----------------------------------------------------------------
    $gcpPaths = @(
        @{ Linux = '/root/.config/gcloud/credentials.db'; Desc = 'root gcloud credentials DB' }
        @{ Linux = '/root/.config/gcloud/access_tokens.db'; Desc = 'root gcloud access tokens' }
        @{ Linux = '/root/.config/gcloud/application_default_credentials.json'; Desc = 'root GCP application default credentials' }
    )

    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            $gcpPaths += @{ Linux = "/home/$($userDir.Name)/.config/gcloud/credentials.db"; Desc = "$($userDir.Name) gcloud credentials" }
            $gcpPaths += @{ Linux = "/home/$($userDir.Name)/.config/gcloud/application_default_credentials.json"; Desc = "$($userDir.Name) GCP default credentials" }
        }
    }

    # Also look for GCP service account JSON files anywhere
    $gcpJsonFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc' -Filter '*.json' -Recurse
    foreach ($jsonFile in $gcpJsonFiles) {
        $content = (Read-ArtifactContent -Path $jsonFile.FullName) -join "`n"
        if ($content -match '"type"\s*:\s*"service_account"') {
            $cloudDetected = $true
            $relativePath = $jsonFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
            $findings.Add((New-Finding -Id 'CLOUD-002' -Severity 'High' -Category $analyzerCategory `
                -Title "GCP service account key file: $relativePath" `
                -Description "A GCP service account JSON key file was found. These keys provide persistent access to Google Cloud resources." `
                -ArtifactPath $jsonFile.FullName `
                -Evidence @("File: $relativePath", "Type: GCP Service Account Key (JSON)") `
                -Recommendation "Rotate this service account key immediately. Use workload identity or metadata-based authentication instead of key files." `
                -MITRE 'T1552.001' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact "GCP service account keys provide persistent access to cloud resources, enabling data exfiltration, resource manipulation, or privilege escalation within GCP."))
        }
    }

    foreach ($gcpPath in $gcpPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $gcpPath.Linux
        if (Test-Path $resolved -PathType Leaf) {
            $cloudDetected = $true
            $findings.Add((New-Finding -Id 'CLOUD-002' -Severity 'High' -Category $analyzerCategory `
                -Title "GCP credential file found: $($gcpPath.Desc)" `
                -Description "GCP credential file detected at $($gcpPath.Linux)." `
                -ArtifactPath $resolved `
                -Evidence @("File: $($gcpPath.Linux)", "Description: $($gcpPath.Desc)") `
                -Recommendation "Review GCP credential files and rotate if compromised. Use workload identity where possible." `
                -MITRE 'T1552.001' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact "GCP credential files enable access to Google Cloud services, potentially allowing data access, infrastructure modification, or privilege escalation."))
        }
    }

    # ----------------------------------------------------------------
    # CLOUD-003: Azure identity/token files
    # ----------------------------------------------------------------
    $azurePaths = @(
        @{ Linux = '/root/.azure/accessTokens.json'; Desc = 'root Azure access tokens' }
        @{ Linux = '/root/.azure/azureProfile.json'; Desc = 'root Azure profile' }
        @{ Linux = '/etc/kubernetes/azure.json'; Desc = 'Azure Kubernetes config' }
    )

    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            $azurePaths += @{ Linux = "/home/$($userDir.Name)/.azure/accessTokens.json"; Desc = "$($userDir.Name) Azure tokens" }
            $azurePaths += @{ Linux = "/home/$($userDir.Name)/.azure/azureProfile.json"; Desc = "$($userDir.Name) Azure profile" }
        }
    }

    foreach ($azPath in $azurePaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $azPath.Linux
        if (Test-Path $resolved -PathType Leaf) {
            $cloudDetected = $true
            $findings.Add((New-Finding -Id 'CLOUD-003' -Severity 'High' -Category $analyzerCategory `
                -Title "Azure credential file found: $($azPath.Desc)" `
                -Description "Azure credential or token file detected at $($azPath.Linux)." `
                -ArtifactPath $resolved `
                -Evidence @("File: $($azPath.Linux)", "Description: $($azPath.Desc)") `
                -Recommendation "Rotate Azure credentials. Use managed identities instead of token files where possible." `
                -MITRE 'T1552.001' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact "Azure credential files enable access to Azure cloud resources, potentially allowing data access, infrastructure modification, or privilege escalation."))
        }
    }

    # ----------------------------------------------------------------
    # CLOUD-004: Cloud metadata indicators
    # ----------------------------------------------------------------
    # Check for cloud metadata service artifacts (e.g., collected cloud-init data)
    $cloudInitPaths = @(
        '/var/lib/cloud/instance/user-data.txt'
        '/var/lib/cloud/instance/vendor-data.txt'
        '/run/cloud-init/instance-data.json'
        '/var/log/cloud-init.log'
        '/var/log/cloud-init-output.log'
    )

    foreach ($ciPath in $cloudInitPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $ciPath
        if (Test-Path $resolved -PathType Leaf) {
            $cloudDetected = $true
            $content = (Read-ArtifactContent -Path $resolved) -join "`n"

            # Check user-data for credentials
            if ($ciPath -match 'user-data' -and ($content -match '(?i)(password|secret|token|api_key)\s*[:=]')) {
                $findings.Add((New-Finding -Id 'CLOUD-004' -Severity 'High' -Category $analyzerCategory `
                    -Title "Cloud-init user-data contains credentials" `
                    -Description "Cloud-init user data at $ciPath appears to contain credential information. User data is often stored unencrypted and accessible via metadata service." `
                    -ArtifactPath $resolved `
                    -Evidence @("File: $ciPath", "Contains credential-like patterns in cloud-init user data") `
                    -Recommendation "Remove credentials from cloud-init user data. Use IAM roles, secrets manager, or encrypted secrets instead." `
                    -MITRE 'T1552.005' `
                    -CVSSv3Score '7.5' `
                    -TechnicalImpact "Credentials in cloud-init user data can be retrieved by any process able to query the metadata service (IMDSv1) or with file system access."))
            }
        }
    }

    # ----------------------------------------------------------------
    # CLOUD-005: Kubernetes service account tokens
    # ----------------------------------------------------------------
    $k8sPaths = @(
        '/var/run/secrets/kubernetes.io/serviceaccount/token'
        '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        '/var/run/secrets/kubernetes.io/serviceaccount/namespace'
    )

    $k8sTokenFound = $false
    foreach ($k8sPath in $k8sPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $k8sPath
        if (Test-Path $resolved -PathType Leaf) {
            $k8sTokenFound = $true
            $cloudDetected = $true
        }
    }

    if ($k8sTokenFound) {
        $findings.Add((New-Finding -Id 'CLOUD-005' -Severity 'Medium' -Category $analyzerCategory `
            -Title "Kubernetes service account token accessible" `
            -Description "Kubernetes service account credentials are accessible in the container. These tokens can be used to interact with the Kubernetes API server." `
            -ArtifactPath '/var/run/secrets/kubernetes.io/serviceaccount/' `
            -Evidence @("Service account token found at /var/run/secrets/kubernetes.io/serviceaccount/token") `
            -Recommendation "Review the RBAC permissions of this service account. Disable auto-mounting if not needed (automountServiceAccountToken: false)." `
            -MITRE 'T1552.001' `
            -CVSSv3Score '6.5' `
            -TechnicalImpact "Kubernetes service account tokens can be used to interact with the K8s API, potentially enabling pod creation, secret access, or cluster compromise."))
    }

    # Also check for kubeconfig files
    $kubeconfigPaths = @('/root/.kube/config')
    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            $kubeconfigPaths += "/home/$($userDir.Name)/.kube/config"
        }
    }

    foreach ($kcPath in $kubeconfigPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $kcPath
        if (Test-Path $resolved -PathType Leaf) {
            $cloudDetected = $true
            $content = (Read-ArtifactContent -Path $resolved) -join "`n"
            $clusterCount = ([regex]::Matches($content, 'cluster:')).Count

            $findings.Add((New-Finding -Id 'CLOUD-005' -Severity 'High' -Category $analyzerCategory `
                -Title "Kubeconfig file found: $kcPath" `
                -Description "A Kubernetes configuration file was found containing cluster credentials and connection information." `
                -ArtifactPath $resolved `
                -Evidence @("File: $kcPath", "Contains $clusterCount cluster configuration(s)") `
                -Recommendation "Review kubeconfig permissions. Ensure it does not contain overprivileged service account tokens." `
                -MITRE 'T1552.001' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact "Kubeconfig files contain cluster authentication tokens that may allow full cluster administration, enabling container deployment, secret access, and infrastructure control."))
        }
    }

    # ----------------------------------------------------------------
    # CLOUD-006: Cloud VM detection from DMI/product info
    # ----------------------------------------------------------------
    $dmiPaths = @(
        '/sys/class/dmi/id/product_name'
        '/sys/class/dmi/id/sys_vendor'
        '/sys/class/dmi/id/bios_vendor'
        '/sys/class/dmi/id/chassis_asset_tag'
    )

    $cloudVendorPatterns = @{
        'Amazon EC2'     = '(?i)(amazon|ec2|aws)'
        'Google Cloud'   = '(?i)(google|gce)'
        'Microsoft Azure'= '(?i)(microsoft|azure|hyper-v)'
        'DigitalOcean'   = '(?i)digitalocean'
        'Alibaba Cloud'  = '(?i)(alibaba|aliyun)'
        'Oracle Cloud'   = '(?i)oracle'
        'VMware'         = '(?i)vmware'
    }

    $detectedCloud = $null
    foreach ($dmiPath in $dmiPaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $dmiPath
        if (-not (Test-Path $resolved -PathType Leaf)) { continue }

        $content = (Read-ArtifactContent -Path $resolved) -join ''
        foreach ($vendor in $cloudVendorPatterns.Keys) {
            if ($content -match $cloudVendorPatterns[$vendor]) {
                $detectedCloud = $vendor
                break
            }
        }
        if ($detectedCloud) { break }
    }

    if ($detectedCloud) {
        $cloudDetected = $true
        $findings.Add((New-Finding -Id 'CLOUD-006' -Severity 'Informational' -Category $analyzerCategory `
            -Title "Cloud VM detected: $detectedCloud" `
            -Description "DMI/product information indicates this system is running on $detectedCloud infrastructure." `
            -ArtifactPath '/sys/class/dmi/id/' `
            -Evidence @("Cloud provider: $detectedCloud") `
            -Recommendation "Verify cloud-specific security controls: instance metadata protection (IMDSv2), security groups, IAM roles, and encryption." `
            -MITRE 'T1580' `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    # Summary
    if ($cloudDetected -or $findings.Count -eq 0) {
        $findings.Add((New-Finding -Id 'CLOUD-INFO' -Severity 'Informational' -Category $analyzerCategory `
            -Title "Cloud security analysis summary" `
            -Description "Cloud environment analysis complete. Cloud presence $(if ($cloudDetected) { 'detected' } else { 'not detected' })." `
            -ArtifactPath $EvidencePath `
            -Evidence @("Cloud environment detected: $cloudDetected", "Cloud-related findings: $($findings.Count)") `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    return $findings.ToArray()
}
