function Import-YamlConfig {
    <#
    .SYNOPSIS
        Imports a YAML configuration file and returns it as a hashtable.
        Uses the powershell-yaml module if available, otherwise falls back to a basic parser.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "YAML config file not found: $Path"
    }

    $content = Get-Content -Path $Path -Raw -ErrorAction Stop

    # Try powershell-yaml module first
    if (Get-Module -ListAvailable -Name 'powershell-yaml' -ErrorAction SilentlyContinue) {
        if (-not (Get-Module -Name 'powershell-yaml' -ErrorAction SilentlyContinue)) {
            Import-Module 'powershell-yaml' -ErrorAction Stop
        }
        return ConvertFrom-Yaml $content
    }

    # Fallback: basic YAML-like parser for simple key-value and list structures
    Write-Warning "powershell-yaml module not found. Using basic parser (install 'powershell-yaml' for full support)."
    return ConvertFrom-BasicYaml -Content $content
}

function ConvertFrom-BasicYaml {
    <#
    .SYNOPSIS
        Basic YAML parser for simple structures (key: value, lists, nested objects).
        Not a full YAML parser - handles the subset used by DefaultRules.yaml.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $result = @{}
    $lines = $Content -split "`n"
    $stack = [System.Collections.Generic.Stack[hashtable]]::new()
    $stack.Push($result)
    $indentStack = [System.Collections.Generic.Stack[int]]::new()
    $indentStack.Push(-1)
    $currentList = $null
    $currentListKey = $null

    foreach ($rawLine in $lines) {
        $line = $rawLine.TrimEnd()

        # Skip empty lines and comments
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
            continue
        }

        $indent = $line.Length - $line.TrimStart().Length
        $trimmed = $line.TrimStart()

        # Pop stack when indentation decreases
        while ($indentStack.Count -gt 1 -and $indent -le $indentStack.Peek()) {
            $indentStack.Pop() | Out-Null
            $stack.Pop() | Out-Null
            $currentList = $null
            $currentListKey = $null
        }

        $current = $stack.Peek()

        # List item
        if ($trimmed.StartsWith('- ')) {
            $value = $trimmed.Substring(2).Trim().Trim("'").Trim('"')

            # Check if it's a list item with key-value pairs (e.g., "- pattern: xxx")
            if ($value -match '^(\w+):\s*(.+)$') {
                $itemKey = $Matches[1]
                $itemValue = $Matches[2].Trim().Trim("'").Trim('"')
                $listItem = @{ $itemKey = $itemValue }

                if ($null -eq $currentList) {
                    $currentList = [System.Collections.Generic.List[object]]::new()
                }
                $currentList.Add($listItem)
                if ($currentListKey -and $current.ContainsKey($currentListKey)) {
                    $current[$currentListKey] = $currentList
                }
            }
            else {
                # Simple list item
                if ($null -eq $currentList) {
                    $currentList = [System.Collections.Generic.List[object]]::new()
                }
                $currentList.Add($value)
                if ($currentListKey -and $current.ContainsKey($currentListKey)) {
                    $current[$currentListKey] = $currentList
                }
            }
        }
        # Key-value pair
        elseif ($trimmed -match '^([^:]+):\s*(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim().Trim("'").Trim('"')

            if ([string]::IsNullOrEmpty($value)) {
                # This key starts a new section (object or list)
                $newSection = @{}
                $current[$key] = $newSection
                $currentList = [System.Collections.Generic.List[object]]::new()
                $currentListKey = $key
                $current[$key] = $currentList
                $stack.Push($current)
                $indentStack.Push($indent)
            }
            else {
                # Simple key-value
                $current[$key] = $value
                $currentList = $null
                $currentListKey = $null
            }
        }
    }

    return $result
}
