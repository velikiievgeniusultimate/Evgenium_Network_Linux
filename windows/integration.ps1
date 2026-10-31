param([string]$Output)
$ErrorActionPreference='Stop'
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim();$package=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64')
$sig=Get-AuthenticodeSignature (Join-Path $package 'wintun.dll');if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard'){throw 'Driver signature'}
# Validate the actual production config, including TUN, WG, all carriers and DNS.
# Xray -test only builds configuration: no routes/firewall/adapter activation.
[Reflection.Assembly]::LoadFile((Join-Path $package 'Evgenium.exe')) | Out-Null
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest -ExecutableDirectory $package
$config=@{schema=1;owner=$script:Sid;private_key='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';profile=@{schema=1;public_key='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=';endpoint='195.209.211.163:51820';address='10.78.0.2/32';mtu=1280};policy=@{applications=@();networks=@();ports=@();dns=@();disabled_base=@();route='auto'};lan=@()}
$core=Invoke-Engine 'render' ($config | ConvertTo-Json -Depth 10 -Compress)
$path=Join-Path $Output 'core-test.json';[IO.File]::WriteAllText($path,$core,(New-Object Text.UTF8Encoding($false)))
$p=Start-Process (Join-Path $package 'xray.exe') -ArgumentList 'run','-test','-config',('"'+$path+'"') -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Output 'core-validate.log') -RedirectStandardError (Join-Path $Output 'core-validate-error.log')
if($p.ExitCode -ne 0){throw 'Production core configuration rejected; see core-validate logs'}
Write-Output 'Pinned Xray, signed Wintun and actual production core configuration: PASS'
