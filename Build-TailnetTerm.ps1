[CmdletBinding()]
param([switch] $Offline)

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

    & $cargo.Source @buildArgs | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Cargo release build failed.' }

    Get-Item -LiteralPath (Join-Path $target 'release\tailnet-term.exe')
} finally {
    Pop-Location
}
