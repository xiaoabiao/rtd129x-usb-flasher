<#
    Build the Windows release packages:

      dist/RTD-Flasher-Setup-<version>.exe        (per-user installer, single file)
      dist/RTD-Flasher-<version>-portable.zip     (unzip and run)
      dist/SHA256SUMS.txt

    Prerequisites: the release binaries already built, e.g.
        cargo build --release -p rtd-cli --features usb
        cargo build --release -p rtd-gui --features usb,screenshot

    Works on a normal Windows machine and on GitHub Actions (windows-latest):
    the installer is compiled with the .NET Framework csc that ships with
    Windows, and app.zip is embedded into it, so no IExpress/WiX/NSIS needed.

    Usage:
        powershell -ExecutionPolicy Bypass -File packaging\build-installer.ps1 -Version 1.0.0
#>
param(
    [string]$Version = '1.0.0',
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot 'dist' }

$release = Join-Path $RepoRoot 'target\release'
$guiExe = Join-Path $release 'rtd-gui.exe'
$cliExe = Join-Path $release 'rtd-flash.exe'
foreach ($f in @($guiExe, $cliExe)) {
    if (-not (Test-Path -LiteralPath $f)) {
        throw "缺少 $f —— 先构建 release 版：cargo build --release -p rtd-cli -p rtd-gui --features usb"
    }
}

# AssemblyVersion needs four numeric parts; tags like v1.2.3-rc1 become 1.2.3.0.
$numeric = ($Version -split '-')[0]
$parts = @($numeric -split '\.')
while ($parts.Count -lt 3) { $parts += '0' }
$asmVersion = ($parts[0..2] -join '.') + '.0'

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ('rtd-flasher-stage-' + [guid]::NewGuid().ToString('N'))
$app = Join-Path $stage 'app'
try {
    Write-Host "[1/4] 准备文件 ($Version)"
    New-Item -ItemType Directory -Force -Path $app, (Join-Path $app 'hwsetting'), (Join-Path $app 'docs'), (Join-Path $app 'driver'), $OutDir | Out-Null

    Copy-Item -LiteralPath $guiExe, $cliExe -Destination $app
    Copy-Item -Path (Join-Path $RepoRoot 'hwsetting\*.bin') -Destination (Join-Path $app 'hwsetting')
    $driver = Join-Path $RepoRoot 'packaging\driver\auto_install_driver_win7up.zip'
    if (Test-Path -LiteralPath $driver) {
        Copy-Item -LiteralPath $driver -Destination (Join-Path $app 'driver')
    } else {
        Write-Warning "没有驱动包 $driver，安装包不会自带驱动"
    }
    foreach ($doc in @('HANDOFF-zh.md', 'PROTOCOL-zh.md')) {
        $p = Join-Path $RepoRoot "docs\$doc"
        if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination (Join-Path $app 'docs') }
    }
    Copy-Item -Path (Join-Path $RepoRoot 'packaging\assets\*') -Destination $app

    Write-Host "[2/4] 打包 app.zip"
    $zip = Join-Path $stage 'app.zip'
    Compress-Archive -Path (Join-Path $app '*') -DestinationPath $zip -CompressionLevel Optimal

    Write-Host "[3/4] 生成安装包（内嵌 app.zip）"
    $csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) {
        $csc = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe'
    }
    if (-not (Test-Path -LiteralPath $csc)) { throw '找不到 .NET Framework csc.exe' }

    $versionCs = Join-Path $stage 'VersionInfo.cs'
    @"
using System.Reflection;
[assembly: AssemblyTitle("RTD129x USB Flash Tool Installer")]
[assembly: AssemblyProduct("RTD-Flasher")]
[assembly: AssemblyCompany("xiaoabiao")]
[assembly: AssemblyVersion("$asmVersion")]
[assembly: AssemblyFileVersion("$asmVersion")]
[assembly: AssemblyInformationalVersion("$Version")]
"@ | Set-Content -LiteralPath $versionCs -Encoding ASCII

    $setup = Join-Path $OutDir "RTD-Flasher-Setup-$Version.exe"
    & $csc /nologo /target:winexe /optimize+ "/out:$setup" `
        "/resource:$zip,app.zip" `
        /r:System.IO.Compression.FileSystem.dll /r:System.IO.Compression.dll /r:System.Windows.Forms.dll `
        (Join-Path $RepoRoot 'packaging\Installer.cs') $versionCs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $setup)) {
        throw "编译安装包失败（csc 退出码 $LASTEXITCODE）"
    }

    Write-Host "[4/4] 生成绿色包与校验和"
    $portable = Join-Path $OutDir "RTD-Flasher-$Version-portable.zip"
    Compress-Archive -Path (Join-Path $app '*') -DestinationPath $portable -CompressionLevel Optimal -Force

    $sums = Join-Path $OutDir 'SHA256SUMS.txt'
    Remove-Item -LiteralPath $sums -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $OutDir -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
        $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$h  $($_.Name)"
    } | Set-Content -LiteralPath $sums -Encoding ASCII

    Write-Host ''
    Get-ChildItem -LiteralPath $OutDir -File | Select-Object Name, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 2) } } | Format-Table -AutoSize
    Write-Host "完成：$OutDir"
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
