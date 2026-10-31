param([string]$Output = (Join-Path $PSScriptRoot 'dist'), [string]$InnoCompiler = '')
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid VERSION' }
$tokens=$null; $errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Evgenium.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { $errors | ForEach-Object { Write-Error $_ }; throw 'PowerShell parse errors' }
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$automation=[Management.Automation.PowerShell].Assembly.Location
$package=Join-Path $Output ('Evgenium-Windows-' + $version + '-x64')
$null=New-Item -ItemType Directory -Force -Path $package
$assembly=Join-Path $Output 'AssemblyInfo.cs'
[IO.File]::WriteAllText($assembly,('[assembly:System.Reflection.AssemblyVersion("'+$version+'.0")][assembly:System.Reflection.AssemblyFileVersion("'+$version+'.0")]'),[Text.Encoding]::UTF8)
$arguments=@('/nologo','/optimize+','/platform:x64','/target:winexe',('/out:'+(Join-Path $package 'Evgenium.exe')),('/reference:'+$automation),'/reference:System.Windows.Forms.dll',('/resource:'+(Join-Path $root 'Evgenium.ps1')+',Evgenium.ps1'),(Join-Path $root 'Host.cs'),(Join-Path $root 'WgProcess.cs'),$assembly)
& $compiler @arguments
if ($LASTEXITCODE -ne 0) { throw 'C# compilation failed' }
Copy-Item -LiteralPath (Join-Path $root 'README.txt') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'VERSION') -Destination $package
foreach ($command in @('selftest','status')) {
 $check=Start-Process -FilePath (Join-Path $package 'Evgenium.exe') -ArgumentList '--command',$command -Wait -PassThru
 if ($check.ExitCode -ne 0) { throw ('Packaged '+$command+' failed') }
}
if (!$InnoCompiler) { $InnoCompiler=Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }
& $InnoCompiler ('/DAppVersion='+$version) ('/DPackageDir='+$package) ('/DOutputDir='+$Output) (Join-Path $root 'installer.iss')
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed' }
$setup=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64-Setup.exe')
# Compatibility archive for 0.1.0's strict four-file updater. This windowed
# alias is NEVER installed by Setup; the next GUI launch migrates to Setup.
$compat=Join-Path $Output 'legacy-compat'; $null=New-Item -ItemType Directory -Force -Path $compat
foreach ($file in @('Evgenium.exe','README.txt','VERSION')) { Copy-Item -LiteralPath (Join-Path $package $file) -Destination $compat }
Copy-Item -LiteralPath (Join-Path $package 'Evgenium.exe') -Destination (Join-Path $compat 'EvgeniumCLI.exe')
$zip=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64.zip')
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip }
Compress-Archive -Path (Join-Path $compat '*') -DestinationPath $zip -CompressionLevel Optimal
$lines=@($setup,$zip) | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($_) }
[IO.File]::WriteAllText((Join-Path $Output 'SHA256SUMS'),(($lines -join "`n")+"`n"),[Text.Encoding]::ASCII)
Write-Output ('INSTALLER='+$setup)
