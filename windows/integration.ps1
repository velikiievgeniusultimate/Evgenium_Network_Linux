# Windows CI integration. No production token, peer, default route or DNS changes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest
if ($global:EvgeniumExitCode -ne 0) { throw 'Self-test failed' }
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('evgenium-integration-'+[Guid]::NewGuid().ToString('N'))
$script:Data=$temporary
Protect-Directory $temporary
$testName='EvgeniumCI'
$serviceName='WireGuardTunnel$EvgeniumCI'
$wg=$null
try {
    $wg=Ensure-WireGuard
    $private=Invoke-Wg 'genkey'; $public=Invoke-Wg 'pubkey' $private
    if (!(Check-Key $private) -or !(Check-Key $public)) { throw 'Official wg.exe key generation failed' }
    $peerPrivate=Invoke-Wg 'genkey'; $peer=Invoke-Wg 'pubkey' $peerPrivate; $peerPrivate=$null
    $config="[Interface]`nPrivateKey = $private`nAddress = 192.0.2.254/32`n`n[Peer]`nPublicKey = $peer`nEndpoint = 127.0.0.1:9`nAllowedIPs = 192.0.2.1/32`n"
    $path=Join-Path $temporary ($testName+'.conf')
    [IO.File]::WriteAllText($path,$config,(New-Object Text.UTF8Encoding($false)))
    $private=$null; $config=$null
    $process=Start-Process -FilePath $wg -ArgumentList @('/installtunnelservice',('"'+$path+'"')) -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw 'Official tunnel installation failed' }
    $service=Get-Service -Name $serviceName
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
    # Public key only; never dump private keys or whole tunnel configuration.
    $installed=Invoke-Wg ('show '+$testName+' public-key')
    if ($installed -cne $public) { throw 'Tunnel public key mismatch' }
    Write-Output 'Official signatures, MSI installation, wg.exe keys, tunnel service and driver: PASS'
} finally {
    if ($wg -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { $null=Start-Process -FilePath $wg -ArgumentList '/uninstalltunnelservice',$testName -PassThru -Wait }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
