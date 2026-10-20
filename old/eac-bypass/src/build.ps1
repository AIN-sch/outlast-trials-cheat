$ErrorActionPreference = 'Stop'

# Layout: this script lives in src\, artifacts land in ..\bin
$src     = $PSScriptRoot
$out     = Join-Path (Split-Path $src -Parent) 'bin'
$mingw   = 'D:\QT\Tools\mingw1310_64\bin'
$gxx     = Join-Path $mingw 'g++.exe'
$windres = Join-Path $mingw 'windres.exe'

if (-not (Test-Path $out))     { New-Item -ItemType Directory -Path $out | Out-Null }
if (-not (Test-Path $gxx))     { throw "g++ not found: $gxx" }
if (-not (Test-Path $windres)) { throw "windres not found: $windres" }

# cc1plus.exe resolves its runtime DLLs next to g++, so the bin directory must be on PATH.
$env:PATH = "$mingw;$env:PATH"

$payloadDll = Join-Path $out 'EACPayload.dll'
$loaderExe  = Join-Path $out 'EACLoader.exe'
$resObj     = Join-Path $src 'payload_res.o'
$manObj     = Join-Path $src 'loader_res.o'

Push-Location $src
try {
    Write-Host '[*] building EACPayload.dll'
    & $gxx -O2 -s -shared -static -static-libgcc -static-libstdc++ `
        -o $payloadDll EACPayload.cpp -luser32 -ladvapi32
    if ($LASTEXITCODE -ne 0) { throw "EACPayload build failed ($LASTEXITCODE)" }

    Write-Host '[*] building payload resource'
    & $windres --include-dir=$out -i payload.rc -o $resObj
    if ($LASTEXITCODE -ne 0) { throw "windres payload.rc failed ($LASTEXITCODE)" }

    Write-Host '[*] building elevation manifest resource'
    & $windres -i loader.rc -o $manObj
    if ($LASTEXITCODE -ne 0) { throw "windres loader.rc failed ($LASTEXITCODE)" }

    Write-Host '[*] building EACLoader.exe'
    & $gxx -O2 -s -o $loaderExe EACLoader.cpp $resObj $manObj `
        -static -static-libgcc -static-libstdc++ -luser32 -ladvapi32
    if ($LASTEXITCODE -ne 0) { throw "EACLoader build failed ($LASTEXITCODE)" }

    Write-Host '[+] build ok'
}
finally {
    Pop-Location
    foreach ($o in @($resObj, $manObj)) { if (Test-Path $o) { Remove-Item $o -Force } }
}

Get-ChildItem $loaderExe, $payloadDll | Select-Object Name, Length | Format-Table -AutoSize

Write-Host '[*] verifying artifacts'
& python (Join-Path $src 'verify_pe.py')
