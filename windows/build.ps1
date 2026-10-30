param([string]$Output = (Join-Path $PSScriptRoot 'dist'))
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid VERSION' }
$tokens=$null; $errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Evgenium.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { $errors | ForEach-Object { Write-Error $_ }; throw 'PowerShell parse errors' }
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$automation=[Management.Automation.PowerShell].Assembly.Location
if (!(Test-Path -LiteralPath $automation)) { throw 'Windows PowerShell reference assembly not found' }
$package=Join-Path $Output ('Evgenium-Windows-' + $version + '-x64')
$null=New-Item -ItemType Directory -Force -Path $package
foreach ($gui in @($true,$false)) {
    $name=if ($gui) { 'Evgenium.exe' } else { 'EvgeniumCLI.exe' }
    $target=if ($gui) { '/target:winexe' } else { '/target:exe' }
    $arguments=@('/nologo','/optimize+','/platform:x64',$target,('/out:'+(Join-Path $package $name)),('/reference:'+$automation),'/reference:System.Windows.Forms.dll',('/resource:'+(Join-Path $root 'Evgenium.ps1')+',Evgenium.ps1'),(Join-Path $root 'Host.cs'),(Join-Path $root 'WgProcess.cs'))
    if (!$gui) { $arguments+= '/define:CONSOLE' }
    & $compiler @arguments
    if ($LASTEXITCODE -ne 0) { throw 'C# compilation failed' }
}
Copy-Item -LiteralPath (Join-Path $root 'README.txt') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'VERSION') -Destination $package
& (Join-Path $package 'EvgeniumCLI.exe') --command selftest
if ($LASTEXITCODE -ne 0) { throw 'Packaged self-test failed' }
& (Join-Path $package 'EvgeniumCLI.exe') --command status
if ($LASTEXITCODE -ne 0) { throw 'Packaged disconnected-status smoke failed' }
$zip=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64.zip')
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip }
Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zip -CompressionLevel Optimal
$hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $Output 'SHA256SUMS'),($hash+'  '+[IO.Path]::GetFileName($zip)+"`n"),[Text.Encoding]::ASCII)
Write-Output ('PACKAGE='+$zip); Write-Output ('SHA256='+$hash)
