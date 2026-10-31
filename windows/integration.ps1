param([string]$Output)
$ErrorActionPreference='Stop'
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim();$package=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64')
$sig=Get-AuthenticodeSignature (Join-Path $package 'wintun.dll');if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard'){throw 'Driver signature'}
# No route or firewall is changed by this configuration validation test.
$config=@{log=@{loglevel='warning'};inbounds=@(@{listen='127.0.0.1';port=0;protocol='socks';settings=@{auth='noauth';udp=$true}});outbounds=@(@{protocol='freedom';tag='direct'})}
$path=Join-Path $Output 'core-test.json';[IO.File]::WriteAllText($path,($config | ConvertTo-Json -Depth 8))
$p=Start-Process (Join-Path $package 'xray.exe') -ArgumentList 'run','-test','-config',('"'+$path+'"') -Wait -PassThru -WindowStyle Hidden
if($p.ExitCode -ne 0){throw 'Bundled core config rejected'}
Write-Output 'Pinned Xray binary, Authenticode-signed Wintun and standalone config validation: PASS'
