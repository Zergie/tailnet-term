<#
.SYNOPSIS
Builds the standard and legacy-support Windows executables with UPX.

.PARAMETER Offline
Skips downloads and automatic tool installation. Requires locally installed
Rust and MSVC build tools, cached Cargo dependencies, and either a cached UPX
archive or an executable supplied with -Upx.

.PARAMETER Upx
Path or command name of an existing UPX executable. Skips the default UPX
download and cache lookup. The script still tests both compressed binaries
with UPX and checks that each is under 1 MB.

.EXAMPLE
.\Build-TailnetTerm.ps1 -Offline -Upx 'C:\Tools\UPX\upx.exe'
#>
[CmdletBinding()]
param(
    [switch] $Offline,
    [string] $Upx
)

$ErrorActionPreference = 'Stop'

function Install-BuildTool {
    param([string] $Uri, [string[]] $InstallerArgs, [string] $Publisher, [string] $Sha256Uri)
    if (!$Publisher -and !$Sha256Uri) { throw "No verification method configured for $Uri." }
    $installer = Join-Path ([IO.Path]::GetTempPath()) "tailnet-term-$([guid]::NewGuid()).exe"
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $installer
        if ($Sha256Uri) {
            $content = (Invoke-WebRequest -Uri $Sha256Uri -UseBasicParsing).Content
            if ($content -is [byte[]]) { $content = [Text.Encoding]::ASCII.GetString($content) }
            $published = ([string] $content).Trim() -split '\s+' | Select-Object -First 1
            if ($published -notmatch '^[0-9a-fA-F]{64}$') { throw 'The published installer checksum is malformed.' }
            if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $published) {
                throw 'The installer checksum does not match the published checksum.'
            }
        }
        if ($Publisher) {
            $signature = Get-AuthenticodeSignature -LiteralPath $installer
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike "*O=$Publisher,*") {
                throw 'The installer signature could not be verified.'
            }
        }
        $process = Start-Process -FilePath $installer -ArgumentList $InstallerArgs -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -eq 3010) { throw 'Installation needs a Windows restart. Restart, then run the build again.' }
        if ($process.ExitCode -ne 0) { throw "Installer failed with exit code $($process.ExitCode)." }
    } finally {
        if (Test-Path -LiteralPath $installer) { Remove-Item -LiteralPath $installer }
    }
}

function Find-Msvc {
    $vswhere = Join-Path "${env:ProgramFiles(x86)}" 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
}

function Find-Upx {
    param([string] $TargetDirectory)
    if ($Upx) {
        $packer = (Get-Command -Name $Upx -CommandType Application | Select-Object -First 1).Source
    } else {
        $version = '5.3.0'
        $asset = "upx-$version-win64"
        $cache = Join-Path $TargetDirectory 'packaging-tools'
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
    return $packer
}

function Compress-TailnetTerm {
    param([IO.FileInfo] $Source, [string] $Destination, [string] $Packer)
    $packed = Join-Path $source.DirectoryName "tailnet-term-packing-$([guid]::NewGuid().ToString('N')).exe"
    try {
        Copy-Item -LiteralPath $source.FullName -Destination $packed
        & $packer --best --lzma $packed | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'UPX packing failed.' }
        & $packer -t $packed | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'UPX integrity check failed.' }
        $size = (Get-Item -LiteralPath $packed).Length
        if ($size -ge 1000000) { throw "Packed executable is $size bytes and must be under 1 MB." }
        Move-Item -LiteralPath $packed -Destination $destination -Force
        Get-Item -LiteralPath $destination
    } finally {
        if (Test-Path -LiteralPath $packed) { Remove-Item -LiteralPath $packed }
    }
}

Push-Location -LiteralPath $PSScriptRoot
try {
    if (!(Find-Msvc)) {
        if ($Offline) { throw 'MSVC C++ Build Tools are required for an offline build.' }
        Write-Host 'Installing Microsoft C++ Build Tools. Windows may request administrator approval.'
        Install-BuildTool -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -Publisher 'Microsoft Corporation' -InstallerArgs @(
            '--quiet', '--wait', '--norestart', '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended'
        )
        if (!(Find-Msvc)) { throw 'The MSVC C++ tools were not detected after installation.' }
    }

    $cargo = Get-Command cargo.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $cargoBin = Join-Path $cargoHome 'bin\cargo.exe'
    if (!$cargo -and (Test-Path -LiteralPath $cargoBin)) {
        $cargo = Get-Command $cargoBin -CommandType Application
    }
    if (!$cargo) {
        if ($Offline) { throw 'Cargo is required for an offline build.' }
        Write-Host 'Installing the Rust stable MSVC toolchain.'
        Install-BuildTool -Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' `
            -Sha256Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe.sha256' -InstallerArgs @(
            '-y', '--default-host', 'x86_64-pc-windows-msvc', '--default-toolchain', 'stable', '--profile', 'minimal'
        )
        $cargo = Get-Command $cargoBin -CommandType Application
    }

    $metadataArgs = @('metadata', '--no-deps', '--format-version=1', '--locked')
    $buildArgs = @('build', '--release', '--locked')
    if ($Offline) {
        $metadataArgs += '--offline'
        $buildArgs += '--offline'
    }
    $metadata = & $cargo.Source @metadataArgs
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $target = ($metadata | ConvertFrom-Json).target_directory

    $packer = Find-Upx $target
    $release = Join-Path $target 'release'
    $standardTarget = Join-Path $target 'standard'
    $legacyTarget = Join-Path $target 'legacy-support'

    Write-Host 'Building standard variant.'
    & $cargo.Source @buildArgs --target-dir $standardTarget | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cargo standard build failed.' }
    $standard = Get-Item -LiteralPath (Join-Path $standardTarget 'release\tailnet-term.exe')

    Write-Host 'Building legacy-support variant.'
    & $cargo.Source @buildArgs --features classic-pty --target-dir $legacyTarget | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cargo legacy-support build failed.' }
    $legacy = Get-Item -LiteralPath (Join-Path $legacyTarget 'release\tailnet-term.exe')

    New-Item -ItemType Directory -Path $release -Force | Out-Null
    Compress-TailnetTerm $standard (Join-Path $release 'tailnet-term.exe') $packer
    Compress-TailnetTerm $legacy (Join-Path $release 'tailnet-term-legacy-support.exe') $packer
} finally {
    Pop-Location
}
