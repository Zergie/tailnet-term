<#
.SYNOPSIS
Builds tailnet-term and publishes it as a GitHub release.

.DESCRIPTION
Sets the version in Cargo.toml and Cargo.lock, runs the tests, builds both variants with UPX,
and writes SHA256SUMS.txt. It then commits "Release vX.Y.Z", creates an
annotated tag, pushes the branch and the tag, and creates the GitHub release with the assets.

The working tree must be clean, the current branch must be main and match origin/main, and the
tag must not exist yet. Requires an authenticated GitHub CLI (gh).

.PARAMETER Version
The new version without a leading "v", for example 0.2.0.

.PARAMETER NotesFile
Markdown file with the release notes. If omitted, the notes list the commits since the previous
tag and explain how to verify the download.

.PARAMETER Draft
Creates the release as a draft. Commit and tag are pushed all the same.

.PARAMETER DryRun
Builds and stages the assets and prints the release notes, but changes nothing in Git or on
GitHub. Cargo.toml and Cargo.lock are restored afterwards.

.EXAMPLE
.\Publish-TailnetTermRelease.ps1 -Version 0.2.0 -DryRun

.EXAMPLE
.\Publish-TailnetTermRelease.ps1 -Version 0.2.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string] $Version,
    [string] $NotesFile,
    [switch] $Draft,
    [switch] $DryRun,
    [string] $Upx
)

$ErrorActionPreference = 'Stop'
$tag = "v$Version"
$branch = 'main'

function Invoke-Native {
    param([string] $Command, [Parameter(ValueFromRemainingArguments)] [string[]] $Arguments)
    $output = & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "'$Command $($Arguments -join ' ')' failed with exit code $LASTEXITCODE." }
    $output
}

function Set-PackageVersion {
    param([string] $Path, [string] $Pattern, [string] $Version)
    $text = [IO.File]::ReadAllText($Path)
    $regex = [regex]::new($Pattern, 'Multiline')
    if (!$regex.IsMatch($text)) { throw "The package version was not found in $Path." }
    $updated = $regex.Replace($text, "`${prefix}$Version`${suffix}", 1)
    [IO.File]::WriteAllText($Path, $updated, [Text.UTF8Encoding]::new($false))
}

Push-Location -LiteralPath $PSScriptRoot
$cargoFiles = @{}
$committed = $false
try {
    # Preconditions: tools, clean tree, up-to-date main, unused tag.
    foreach ($tool in 'git', 'gh', 'cargo') {
        if (!(Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue)) { throw "$tool was not found in PATH." }
    }
    if (!$DryRun) {
        & gh auth status *> $null
        if ($LASTEXITCODE -ne 0) { throw 'The GitHub CLI is not signed in. Run "gh auth login" first.' }
    }
    # A dry run reports failed preconditions as warnings so it also works on unfinished changes.
    $problems = @()
    if (Invoke-Native git status --porcelain) { $problems += 'The working tree has uncommitted changes. Commit or stash them first.' }
    $current = Invoke-Native git branch --show-current
    if ($current -ne $branch) { $problems += "Releases are made from $branch, but the current branch is '$current'." }
    Invoke-Native git fetch --quiet --tags origin $branch | Out-Null
    if ((Invoke-Native git rev-parse HEAD) -ne (Invoke-Native git rev-parse "origin/$branch")) {
        $problems += "$branch differs from origin/$branch. Pull or push first."
    }
    & git rev-parse --quiet --verify "refs/tags/$tag" *> $null
    if ($LASTEXITCODE -eq 0) { $problems += "Tag $tag already exists." }
    if (Invoke-Native git ls-remote --tags origin "refs/tags/$tag") { $problems += "Tag $tag already exists on origin." }
    if ($problems -and !$DryRun) { throw ($problems -join ' ') }
    $problems | ForEach-Object { Write-Warning $_ }

    $previousTag = & git describe --tags --abbrev=0 HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $previousTag = $null }

    if ($NotesFile) {
        $notes = Get-Content -LiteralPath $NotesFile -Raw
    } else {
        $range = if ($previousTag) { "$previousTag..HEAD" } else { 'HEAD' }
        $changes = Invoke-Native git log --no-merges --format='- %s' $range
        if (!$changes) { throw "There are no commits since $previousTag." }
        $since = if ($previousTag) { " since $previousTag" } else { '' }
        $notes = @"
## Changes$since

$($changes -join "`n")

## Download

``tailnet-term-$Version-windows-x64.exe`` uses ConPTY for interactive sessions. The ``legacy-support`` variant also supports Windows Server 2016 through the classic Windows console backend. Both downloads are standalone executables compressed with UPX.

Verify the download against ``SHA256SUMS.txt``:

``````powershell
(Get-FileHash .\tailnet-term-$Version-windows-x64.exe -Algorithm SHA256).Hash
``````

Built locally with ``Publish-TailnetTermRelease.ps1`` (``cargo build --release --locked``, x86_64-pc-windows-msvc). The executables are not code-signed, so Windows SmartScreen may warn on first run.
"@
    }

    # Version bump; restored on failure or after a dry run.
    foreach ($file in 'Cargo.toml', 'Cargo.lock') {
        $cargoFiles[$file] = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $file))
    }
    Set-PackageVersion (Join-Path $PSScriptRoot 'Cargo.toml') `
        '(?<prefix>^\[package\][^\[]*?^version\s*=\s*")[^"]+(?<suffix>")' $Version
    Set-PackageVersion (Join-Path $PSScriptRoot 'Cargo.lock') `
        '(?<prefix>^name = "tailnet-term"\r?\nversion = ")[^"]+(?<suffix>")' $Version

    Write-Host 'Running tests.'
    & cargo test --locked | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'The tests failed.' }

    Write-Host 'Building release executables.'
    $executables = & (Join-Path $PSScriptRoot 'Build-TailnetTerm.ps1') -Upx:$Upx
    $metadata = Invoke-Native cargo metadata --no-deps --format-version=1 --locked | ConvertFrom-Json

    $staging = Join-Path $metadata.target_directory "release-$tag"
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging | Out-Null
    $assets = foreach ($executable in $executables) {
        $suffix = $executable.Name.Substring('tailnet-term'.Length)
        Copy-Item -LiteralPath $executable.FullName `
            -Destination (Join-Path $staging "tailnet-term-$Version-windows-x64$suffix") -PassThru
    }
    $sums = Join-Path $staging 'SHA256SUMS.txt'
    $lines = foreach ($asset in $assets) {
        "$((Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash.ToLowerInvariant()) *$($asset.Name)"
    }
    [IO.File]::WriteAllText($sums, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    $notesPath = Join-Path $staging 'RELEASE_NOTES.md'
    [IO.File]::WriteAllText($notesPath, $notes, [Text.UTF8Encoding]::new($false))

    if ($DryRun) {
        Write-Host "`nDry run: assets staged in $staging"
        Get-ChildItem -LiteralPath $staging | Format-Table Name, Length | Out-Host
        Write-Host "Release notes for ${tag}:`n"
        Write-Host $notes
        return
    }

    Invoke-Native git add Cargo.toml Cargo.lock | Out-Null
    Invoke-Native git commit --quiet -m "Release $tag" | Out-Null
    $committed = $true
    Invoke-Native git tag --annotate $tag -m "tailnet-term $Version" | Out-Null
    Invoke-Native git push --quiet --atomic origin $branch "refs/tags/$tag" | Out-Null

    $releaseArgs = @(
        'release', 'create', $tag,
        '--title', "tailnet-term $Version",
        '--notes-file', $notesPath,
        '--verify-tag'
    )
    if ($Draft) { $releaseArgs += '--draft' }
    $releaseArgs += @($assets.FullName) + $sums
    $url = Invoke-Native gh @releaseArgs
    Write-Host "Published $tag`: $url"
} catch {
    if ($committed) {
        Write-Warning "Release commit for $tag exists locally. Check 'git log', 'git tag' and origin before retrying."
    }
    throw
} finally {
    if (!$committed) {
        foreach ($file in $cargoFiles.Keys) {
            [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot $file), $cargoFiles[$file])
        }
    }
    Pop-Location
}
