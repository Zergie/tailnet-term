[CmdletBinding()]
param(
    [string] $Upx,
    [switch] $Offline
)

$ErrorActionPreference = 'Stop'
$source = & (Join-Path $PSScriptRoot 'Build-TailnetTerm.ps1') -Offline:$Offline

if ($Upx) {
    $packer = (Get-Command -Name $Upx -CommandType Application | Select-Object -First 1).Source
} else {
    $version = '5.3.0'
    $asset = "upx-$version-win64"
    $cache = Join-Path $source.Directory.Parent.FullName 'packaging-tools'
    $archive = Join-Path $cache "$asset.zip"
    $hash = 'D127996C76615E431BE810E9C8D2910DBE3DD400600C5C0C50276FC5A17A9705'
    if (!(Test-Path -LiteralPath $archive)) {
        if ($Offline) { throw 'UPX is not cached. Run once online or supply -Upx.' }
        New-Item -ItemType Directory -Path $cache -Force | Out-Null
        $download = Join-Path $cache "$([guid]::NewGuid()).zip"
        try {
            Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v$version/$asset.zip" -OutFile $download
            if ((Get-FileHash -LiteralPath $download).Hash -ne $hash) { throw 'UPX download checksum mismatch.' }
            Move-Item -LiteralPath $download -Destination $archive -Force
        } finally {
            if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download }
        }
    }
    if ((Get-FileHash -LiteralPath $archive).Hash -ne $hash) { throw 'Cached UPX checksum mismatch.' }
    Expand-Archive -LiteralPath $archive -DestinationPath $cache -Force
    $packer = Join-Path $cache "$asset\upx.exe"
}

$release = $source.DirectoryName
$destination = Join-Path $release 'tailnet-term-packed.exe'
$packed = Join-Path $release "tailnet-term-packing-$([guid]::NewGuid().ToString('N')).exe"
try {
    Copy-Item -LiteralPath $source.FullName -Destination $packed
    & $packer --best --lzma $packed
    if ($LASTEXITCODE -ne 0) { throw 'UPX packing failed.' }

    & $packer -t $packed
    if ($LASTEXITCODE -ne 0) { throw 'UPX integrity check failed.' }

    Move-Item -LiteralPath $packed -Destination $destination -Force
    $size = (Get-Item -LiteralPath $destination).Length
    Write-Output "$destination ($size bytes)"
} finally {
    if (Test-Path -LiteralPath $packed) { Remove-Item -LiteralPath $packed }
}
