param([string]$Output)
$ErrorActionPreference='Stop'
$stage=Join-Path $Output 'package';$null=New-Item -ItemType Directory -Force $stage
& dotnet publish (Join-Path $PSScriptRoot 'EvgeniumWidget.csproj') -c Release -r win-x64 --self-contained true -o $stage
if($LASTEXITCODE -ne 0){throw 'Widget compilation failed'}
$p=Start-Process (Join-Path $stage 'EvgeniumWidget.exe') -ArgumentList '--selftest' -Wait -PassThru
if($p.ExitCode -ne 0){throw 'Widget card self-test failed'}
Copy-Item (Join-Path $PSScriptRoot 'Package.appxmanifest') (Join-Path $stage 'AppxManifest.xml')
Copy-Item (Join-Path $PSScriptRoot 'README.txt') $stage
$assets=Join-Path $stage 'Assets';$null=New-Item -ItemType Directory -Force $assets
foreach($file in @('app-256.png','app-150.png','app-50.png','app-44.png','widget-preview.png')){Copy-Item (Join-Path $PSScriptRoot ('../Assets/'+$file)) $assets}
$null=New-Item -ItemType Directory -Force (Join-Path $stage 'Public')
$make=Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" | Sort-Object FullName | Select-Object -Last 1
if(!$make){throw 'Windows SDK MakeAppx unavailable'}
& $make.FullName pack /d $stage /p (Join-Path $Output 'Evgenium-Widget-UNSIGNED.msix') /o
if($LASTEXITCODE -ne 0){throw 'Widget package validation failed'}
Copy-Item (Join-Path $PSScriptRoot 'README.txt') $Output
Write-Output 'Widget provider compiled; card states passed; unsigned MSIX validated. NOT installed or published. Win+W and trusted signing remain untested.'
