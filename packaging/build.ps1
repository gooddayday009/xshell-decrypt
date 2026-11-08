param([string]$MakensisPath, [switch]$Offline)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    if (-not $MakensisPath) {
        $command = Get-Command makensis.exe -ErrorAction SilentlyContinue
        if ($command) { $MakensisPath = $command.Source }
        else { $MakensisPath = Join-Path ${env:ProgramFiles(x86)} 'NSIS\makensis.exe' }
    }
    if (-not (Test-Path -LiteralPath $MakensisPath)) { throw 'NSIS not found. Install NSIS 3 or pass -MakensisPath.' }
    $cargoNetworkArgs = @()
    if ($Offline) { $cargoNetworkArgs += '--offline' }
    $manifest = (& cargo metadata --no-deps --format-version 1 --locked @cargoNetworkArgs) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Package metadata failed' }
    $version = ($manifest.packages | Where-Object name -EQ 'xdecrypt-rust').version
    if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Installer requires a numeric major.minor.patch version' }
    & cargo build --release --locked @cargoNetworkArgs
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed' }
    $metadataText = & cargo metadata --format-version 1 --locked --filter-platform x86_64-pc-windows-msvc @cargoNetworkArgs
    if ($LASTEXITCODE -ne 0) { throw 'Dependency metadata failed' }
    $metadata = $metadataText | ConvertFrom-Json
    $notices = [System.Text.StringBuilder]::new()
    [void]$notices.AppendLine("Third-party dependency notices for Xdecrypt Rust $version")
    [void]$notices.AppendLine('Algorithm references and compatibility limits: see README.md.')
    foreach ($package in ($metadata.packages | Where-Object source | Sort-Object name, version)) {
        [void]$notices.AppendLine("`n================ $($package.name) $($package.version) ================")
        [void]$notices.AppendLine("License: $($package.license)")
        [void]$notices.AppendLine("Repository: $($package.repository)")
        $packageRoot = Split-Path -Parent $package.manifest_path
        foreach ($file in (Get-ChildItem -LiteralPath $packageRoot -File | Where-Object Name -Match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)')) {
            [void]$notices.AppendLine("--- $($file.Name) ---")
            [void]$notices.AppendLine([System.IO.File]::ReadAllText($file.FullName))
        }
    }
    [System.IO.File]::WriteAllText((Join-Path $projectRoot 'THIRD_PARTY_NOTICES.txt'), $notices.ToString())
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    & $MakensisPath /V2 /INPUTCHARSET UTF8 "/DPROJECT_ROOT=$projectRoot" "/DAPP_VERSION=$version" (Join-Path $PSScriptRoot 'installer.nsi')
    if ($LASTEXITCODE -ne 0) { throw 'NSIS build failed' }
    $portable = "dist\Xdecrypt-Rust-$version-windows-x64-portable.zip"
    $source = "dist\Xdecrypt-Rust-$version-source.zip"
    $setup = "dist\Xdecrypt-Rust-$version-windows-x64-setup.exe"
    Compress-Archive -LiteralPath 'target\release\xdecrypt-rust.exe','README.md','THIRD_PARTY_NOTICES.txt' -DestinationPath $portable -Force
    Compress-Archive -LiteralPath '.cargo','.github','.gitignore','src','tests','packaging','Cargo.toml','Cargo.lock','README.md','THIRD_PARTY_NOTICES.txt' -DestinationPath $source -Force
    Get-FileHash -LiteralPath $setup,$portable,$source -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $(Split-Path -Leaf $_.Path)" } | Set-Content -LiteralPath 'dist\SHA256SUMS.txt' -Encoding utf8
} finally { Pop-Location }
