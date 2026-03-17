function Import-ScanRules {
    <#
    .SYNOPSIS
        Loads custom YAML rules and merges with or replaces the default rules.
    .DESCRIPTION
        Imports a user-provided YAML rules file for custom detection patterns,
        IOCs, and security signatures. Can extend or replace the built-in rules.
    .PARAMETER Path
        Path to the custom YAML rules file.
    .PARAMETER ReplaceDefaults
        If specified, replaces all default rules instead of merging.
    .EXAMPLE
        Import-ScanRules -Path './custom-rules.yaml'
    .EXAMPLE
        Import-ScanRules -Path './custom-rules.yaml' -ReplaceDefaults
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path,

        [switch]$ReplaceDefaults
    )

    $customRules = Import-YamlConfig -Path $Path

    if ($ReplaceDefaults) {
        $Script:DefaultRules = $customRules
        Write-Host "[*] Custom rules loaded (replaced defaults): $Path" -ForegroundColor Cyan
    }
    else {
        # Merge custom rules into defaults
        if ($null -eq $Script:DefaultRules) {
            $Script:DefaultRules = $customRules
        }
        else {
            foreach ($key in $customRules.Keys) {
                if ($Script:DefaultRules.ContainsKey($key)) {
                    if ($Script:DefaultRules[$key] -is [System.Collections.IList] -and $customRules[$key] -is [System.Collections.IList]) {
                        # Append list items
                        foreach ($item in $customRules[$key]) {
                            $Script:DefaultRules[$key].Add($item)
                        }
                    }
                    elseif ($Script:DefaultRules[$key] -is [hashtable] -and $customRules[$key] -is [hashtable]) {
                        # Merge hashtables
                        foreach ($subKey in $customRules[$key].Keys) {
                            $Script:DefaultRules[$key][$subKey] = $customRules[$key][$subKey]
                        }
                    }
                    else {
                        $Script:DefaultRules[$key] = $customRules[$key]
                    }
                }
                else {
                    $Script:DefaultRules[$key] = $customRules[$key]
                }
            }
        }
        Write-Host "[*] Custom rules merged with defaults: $Path" -ForegroundColor Cyan
    }

    return $Script:DefaultRules
}
