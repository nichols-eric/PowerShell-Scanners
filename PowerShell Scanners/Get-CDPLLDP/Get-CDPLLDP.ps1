<#
.SYNOPSIS
    Ultra-silent pktmon CDP/LLDP discovery with
cleaned neighbor/port strings.
#>
[CmdletBinding()]
param (
    [int]$MaxAttempts = 10,
    [int]$CaptureSecondsPerAttempt = 30,
    [switch]$IncludeLLDP = $true,
    [switch]$ClearCache
)

# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    return [PSCustomObject]@{
        Date               = Get-Date
        NeighborDeviceName = "ERROR: Administrator privileges required"
        NeighborDevicePort = "ERROR: Administrator privileges required"
        Protocol           = "N/A"
    }
}

$CacheFile = Join-Path $env:TEMP -ChildPath "CDP_LLDPCache.json"

# Load cache - wrapped Test-Path in parentheses to prevent parameter errors
if ((Test-Path $CacheFile) -and -not $ClearCache) {
    try {
        $CachedRecords = Get-Content $CacheFile -Raw | ConvertFrom-Json
    } catch { 
        $CachedRecords = @() 
    }
} else {
    $CachedRecords = @()
}

# Check Ethernet
$EthernetUp = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' -and $_.MediaType -eq '802.3' }

if (-not $EthernetUp) {
    if ($CachedRecords.Count -eq 0) {
        return [PSCustomObject]@{
            Date               = Get-Date
            NeighborDeviceName = "No neighbor found"
            NeighborDevicePort = "No neighbor found"
            Protocol           = "N/A"
        }
    } else {
        return $CachedRecords
    }
}

# === Ethernet connected - capture ===
$Seen = @{}
$NewResults = @()

foreach ($item in $CachedRecords) {
    $Key = "$($item.NeighborDeviceName)|$($item.NeighborDevicePort)"
    if (-not $Seen.ContainsKey($Key)) {
        $Seen[$Key] = $true 
    }
}

for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $EtlFile = Join-Path $env:TEMP -ChildPath "Discovery_${Timestamp}.etl"
    $TxtFile = $EtlFile -replace '\.etl$', '.txt'

    try {
        pktmon filter remove *> $null 2>&1
        pktmon filter add -m 01-00-0C-CC-CC-CC *> $null 2>&1
        if ($IncludeLLDP) {
            pktmon filter add -d 0x88cc *> $null 2>&1
        }

        pktmon start --capture --pkt-size 0 --file-name $EtlFile --comp nics *> $null 2>&1
        Start-Sleep -Seconds $CaptureSecondsPerAttempt
        pktmon stop *> $null 2>&1

        pktmon etl2txt $EtlFile -o $TxtFile --verbose 3 *> $null 2>&1

        $Content = Get-Content $TxtFile -Raw -ErrorAction SilentlyContinue
        if (-not $Content) { continue }

        # Improved regex - much stricter cleanup
        $DeviceRegex = [regex]::new('(?i)(?:Device-ID|Chassis ID|System Name)[\s:]+(.+?)(?:\s*(?:value length|bytes|TLV|\(|,|\r|$))', 'IgnoreCase')
        $PortRegex   = [regex]::new('(?i)(?:Port-ID|Port ID)[\s:]+(.+?)(?:\s*(?:value length|bytes|TLV|Subtype|\(|,|\r|$))', 'IgnoreCase')

        $Sections = $Content -split '(?i)\[\d+\]\d{4}\.\d+::'

        foreach ($Section in $Sections) {
            $DeviceMatch = $DeviceRegex.Match($Section)
            $PortMatch   = $PortRegex.Match($Section)

            if ($DeviceMatch.Success -and $PortMatch.Success) {
                # Extra aggressive trim
                $Device = $DeviceMatch.Groups[1].Value.Trim(" '`",")
                $Port   = $PortMatch.Groups[1].Value.Trim(" '`",")

                # Remove any remaining trailing junk like "bytes:" or hex
                $Device = $Device -replace '\s*value length.*$', '' -replace '\s*0x.*$', ''
                $Port   = $Port -replace '\s*value length.*$', '' -replace '\s*0x.*$', ''

                $Key = "$Device|$Port"
                if (-not $Seen.ContainsKey($Key) -and $Device.Length -gt 1 -and $Port.Length -gt 1) {
                    $Seen[$Key] = $true

                    $NewResults += [PSCustomObject]@{
                        Date               = Get-Date
                        NeighborDeviceName = $Device
                        NeighborDevicePort = $Port
                        Protocol           = if ($Section -match '0x88cc|LLDP') { "LLDP" } else { "CDP" }
                    }
                }
            }
        }

        if ($NewResults.Count -gt 0) {
            break
        }
    }
    finally {
        @($EtlFile, $TxtFile) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
        }
    }

    if ($Attempt -lt $MaxAttempts) {
        Start-Sleep -Seconds 5
    }
}

# Merge + keep last 5
$AllRecords = $NewResults + $CachedRecords
$FinalRecords = $AllRecords | Select-Object -First 5

# Save cache
$FinalRecords | ConvertTo-Json -Depth 3 | Set-Content $CacheFile -Force

# Cleanup pktmon filters before exiting
pktmon filter remove *> $null 2>&1

# Return Results
if ($FinalRecords.Count -eq 0) {
    return [PSCustomObject]@{
        Date               = Get-Date
        NeighborDeviceName = "No neighbor found"
        NeighborDevicePort = "No neighbor found"
        Protocol           = "N/A"
    }
} else {
    return $FinalRecords
}
