function Read-ArtifactContent {
    <#
    .SYNOPSIS
        Safely reads the content of a Linux artifact file with encoding handling.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxLines = 0
    )

    if (-not (Test-Path $Path -PathType Leaf)) {
        Write-Verbose "Artifact not found: $Path"
        return @()
    }

    try {
        $content = Get-Content -Path $Path -ErrorAction Stop -Encoding utf8

        if ($MaxLines -gt 0 -and $content.Count -gt $MaxLines) {
            $content = $content | Select-Object -First $MaxLines
        }

        return $content
    }
    catch {
        # Fallback: try reading as raw bytes and converting
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            $lines = $text -split "`n"

            if ($MaxLines -gt 0 -and $lines.Count -gt $MaxLines) {
                $lines = $lines | Select-Object -First $MaxLines
            }

            return $lines
        }
        catch {
            Write-Warning "Failed to read artifact: $Path - $_"
            return @()
        }
    }
}
