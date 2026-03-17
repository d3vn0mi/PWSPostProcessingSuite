function Resolve-ArtifactPath {
    <#
    .SYNOPSIS
        Maps a Linux filesystem path to the corresponding path within the evidence folder.
        Handles both filesystem-mirror and flat-collection structures.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$EvidencePath,

        [Parameter(Mandatory)]
        [string]$LinuxPath
    )

    # Normalize the Linux path - strip leading /
    $relativePath = $LinuxPath.TrimStart('/')

    # Strategy 1: Direct filesystem mirror (evidence_root/etc/passwd)
    $mirrorPath = Join-Path $EvidencePath $relativePath
    if (Test-Path $mirrorPath) {
        return $mirrorPath
    }

    # Strategy 2: Try with OS-appropriate separators
    $normalizedRelative = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $normalizedPath = Join-Path $EvidencePath $normalizedRelative
    if (Test-Path $normalizedPath) {
        return $normalizedPath
    }

    # Strategy 3: Flat collection - look for the filename anywhere under evidence root
    $fileName = Split-Path $LinuxPath -Leaf
    $flatMatches = Get-ChildItem -Path $EvidencePath -Recurse -Filter $fileName -File -ErrorAction SilentlyContinue
    if ($flatMatches) {
        # If multiple matches, prefer the one whose parent path most closely matches
        $pathParts = $relativePath.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)
        $bestMatch = $null
        $bestScore = -1

        foreach ($match in $flatMatches) {
            $score = 0
            $matchDir = $match.DirectoryName
            foreach ($part in $pathParts) {
                if ($matchDir -like "*$part*") {
                    $score++
                }
            }
            if ($score -gt $bestScore) {
                $bestScore = $score
                $bestMatch = $match
            }
        }

        if ($bestMatch) {
            return $bestMatch.FullName
        }
    }

    # Not found - return the mirror path (caller should check existence)
    return $mirrorPath
}
