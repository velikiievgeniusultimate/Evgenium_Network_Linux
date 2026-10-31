param([string]$Output=(Join-Path $PSScriptRoot 'dist'),[string]$InnoCompiler='', [string]$TestVersion='')
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$version=(Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw -Encoding UTF8).Trim()
if ($TestVersion) {if($env:GITHUB_ACTIONS -ne 'true'){throw 'Version fixtures are CI only'};$version=$TestVersion}
if ($version -notmatch '^\d+\.\d+\.\d+$') {throw 'Invalid VERSION'}
$package=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64');$null=New-Item -ItemType Directory -Force -Path $package
$bundle=Join-Path $Output 'Bundle.ps1'
$text=@('Evgenium.ps1','Policy.ps1','Reports.ps1','Desktop.ps1','Entry.ps1') | ForEach-Object {Get-Content -LiteralPath (Join-Path $root $_) -Raw -Encoding UTF8}
$content=($text -join "`r`n").Replace("`$script:Version = '"+(Get-Content (Join-Path $root 'VERSION') -Raw -Encoding UTF8).Trim()+"'",("`$script:Version = '"+$version+"'"))
[IO.File]::WriteAllText($bundle,$content,[Text.Encoding]::UTF8)
$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($bundle,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$assembly=Join-Path $Output 'AssemblyInfo.cs'
[IO.File]::WriteAllText($assembly,('[assembly:System.Reflection.AssemblyVersion("'+$version+'.0")][assembly:System.Reflection.AssemblyFileVersion("'+$version+'.0")]'),[Text.Encoding]::UTF8)
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$automation=[Management.Automation.PowerShell].Assembly.Location
& $compiler '/nologo' '/codepage:65001' '/optimize+' '/platform:x64' '/target:winexe' ('/win32manifest:'+(Join-Path $root 'app.manifest')) ('/out:'+(Join-Path $package 'Evgenium.exe')) ('/reference:'+$automation) '/reference:System.Windows.Forms.dll' '/reference:System.Drawing.dll' '/reference:System.Web.Extensions.dll' '/reference:System.Xaml.dll' ('/reference:'+(Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\WPF\WindowsBase.dll')) ('/reference:'+(Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\WPF\PresentationCore.dll')) ('/reference:'+(Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\WPF\PresentationFramework.dll')) ('/win32icon:'+(Join-Path $root 'Assets\Evgenium.ico')) ('/resource:'+(Join-Path $root 'Assets\Evgenium.ico')+',Evgenium.Evgenium.ico') ('/resource:'+(Join-Path $root 'Assets\app-256.png')+',Evgenium.app-256.png') ('/resource:'+(Join-Path $root 'Desktop.xaml')+',Evgenium.Desktop.xaml') ('/resource:'+$bundle+',Evgenium.ps1') (Join-Path $root 'Host.cs') (Join-Path $root 'ProcessRunner.cs') (Join-Path $root 'Desktop.cs') $assembly
if($LASTEXITCODE -ne 0){throw 'GUI compilation failed'}
Add-Type -AssemblyName System.Drawing
$icon=[Drawing.Icon]::ExtractAssociatedIcon((Join-Path $package 'Evgenium.exe'));$bitmap=$icon.ToBitmap()
try{$accent=0;for($x=0;$x -lt $bitmap.Width;$x++){for($y=0;$y -lt $bitmap.Height;$y++){$c=$bitmap.GetPixel($x,$y);if($c.R -gt 200 -and $c.G -lt 160 -and $c.B -lt 180){$accent++}}};if($accent -lt 10){throw 'Executable lacks the drill icon'}}finally{$bitmap.Dispose();$icon.Dispose()}

Push-Location (Join-Path $root 'engine')
try {& go build -trimpath -ldflags ('-s -w -H=windowsgui -X main.version='+$version) -o (Join-Path $package 'EvgeniumEngine.exe') .;if($LASTEXITCODE -ne 0){throw 'Engine compilation failed'}} finally {Pop-Location}
$cache=Join-Path $env:RUNNER_TEMP 'evgenium-xray-26.10.29.zip'
if(!(Test-Path $cache)){Invoke-WebRequest -UseBasicParsing 'https://github.com/XTLS/Xray-core/releases/download/v26.10.29/Xray-windows-64.zip' -OutFile $cache}
if((Get-FileHash $cache).Hash.ToLowerInvariant() -ne 'fce33e81cccf50e7aab572b175519a50b5e0f9d2f5c8d1ed73012ea5c9ad4d58'){throw 'Xray archive checksum mismatch'}
$unpack=Join-Path $Output 'xray';Expand-Archive $cache $unpack -Force
foreach($file in @('xray.exe','wintun.dll','LICENSE-Wintun')){Copy-Item -LiteralPath (Join-Path $unpack $file) -Destination $package}
Copy-Item -LiteralPath (Join-Path $unpack 'LICENSE') -Destination (Join-Path $package 'LICENSE-Xray')
foreach($license in Get-ChildItem -LiteralPath $root -Filter 'LICENSE-*.txt'){Copy-Item -LiteralPath $license.FullName -Destination $package}
$sig=Get-AuthenticodeSignature -LiteralPath (Join-Path $package 'wintun.dll')
if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard'){throw 'Wintun signature not verified'}
Copy-Item -LiteralPath (Join-Path $root 'README.txt') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'Evgenium.exe.config') -Destination $package
[IO.File]::WriteAllText((Join-Path $package 'VERSION'),$version,[Text.Encoding]::ASCII)
foreach($command in @('selftest','status','ui-selftest')){$p=Start-Process -FilePath (Join-Path $package 'Evgenium.exe') -ArgumentList '--command',$command -PassThru;if(!$p.WaitForExit(120000)){$p.Kill();throw ('Packaged '+$command+' timed out')};if($p.ExitCode -ne 0){throw ('Packaged '+$command+' failed')}}
if(!$InnoCompiler){$InnoCompiler=Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'}
& $InnoCompiler ('/DAppVersion='+$version) ('/DPackageDir='+$package) ('/DOutputDir='+$Output) (Join-Path $root 'installer.iss')
if($LASTEXITCODE -ne 0){throw 'Installer compilation failed'}
$setup=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64-Setup.exe')
[IO.File]::WriteAllText((Join-Path $Output 'SHA256SUMS'),((Get-FileHash $setup).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($setup)+"`n"),[Text.Encoding]::ASCII)
Write-Output ('INSTALLER='+$setup)
