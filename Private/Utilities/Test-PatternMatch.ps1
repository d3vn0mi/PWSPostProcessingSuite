function Test-PatternMatch {
    <#
    .SYNOPSIS
        Tests a line of text against a set of detection patterns from the rules engine.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$InputText,

        [Parameter(Mandatory)]
        [array]$Patterns
    )

    foreach ($rule in $Patterns) {
        $pattern = $rule.pattern
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }

        try {
            if ($InputText -match $pattern) {
                return [PSCustomObject]@{
                    Matched  = $true
                    Pattern  = $pattern
                    Severity = if ($rule.severity) { $rule.severity } else { 'Medium' }
                    MITRE    = if ($rule.mitre) { $rule.mitre } else { '' }
                    RuleName = if ($rule.name) { $rule.name } else { '' }
                }
            }
        }
        catch {
            Write-Verbose "Invalid regex pattern '$pattern': $_"
        }
    }

    return [PSCustomObject]@{
        Matched  = $false
        Pattern  = ''
        Severity = ''
        MITRE    = ''
        RuleName = ''
    }
}
