# Destructive install/uninstall checks: disposable GitHub Windows runner ONLY.
param([string]$Output)
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Installer test requires a disposable hosted runner' }
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim()
$setup=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64-Setup.exe')
$app=Join-Path $env:LOCALAPPDATA 'Programs\EvgeniumNetwork'
$key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{53E2495A-A134-40DC-BA91-D2FD582DE3AD}_is1'
if ((Test-Path $app) -or (Test-Path $script:AppRoot) -or (Get-Service -Name $script:Service -ErrorAction SilentlyContinue)) { throw 'Unexpected previous installation; refusing test' }
Protect-Directory $script:Data
$state=Read-State; $state.token=Seal ('EVN1-'+('a'*43)); Save-State $state
$before=(Get-FileHash $script:StatePath).Hash
$legacy=Join-Path $script:AppRoot 'versions\0.1.0'; $null=New-Item -ItemType Directory -Force -Path $legacy
[IO.File]::WriteAllText((Join-Path $legacy 'EvgeniumCLI.exe'),'legacy marker')
[IO.File]::WriteAllText((Join-Path $script:AppRoot 'current.txt'),'0.1.0')
function Run-Setup {
 $p=Start-Process $setup -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOLAUNCH',('/LOG="'+(Join-Path $Output 'install.log')+'"') -Wait -PassThru
 if ($p.ExitCode -ne 0) { throw ('Setup exit '+$p.ExitCode) }
 if (!(Test-Path (Join-Path $app 'Evgenium.exe')) -or (Test-Path (Join-Path $app 'EvgeniumCLI.exe'))) { throw 'GUI-only installation failed' }
 if ((Get-ItemProperty $key).DisplayVersion -ne $version) { throw 'Windows Apps registration missing' }
 if ((Get-FileHash $script:StatePath).Hash -ne $before) { throw 'Upgrade changed credentials/device identity' }
}
Run-Setup
if (Test-Path (Join-Path $script:AppRoot 'versions')) { throw 'Legacy binaries remain' }
Run-Setup
Write-Output 'Fresh setup, legacy migration and repeat setup preserve encrypted token: PASS'
# Test removal while our real driver service is running, without any default route.
$wg=Ensure-WireGuard
$private=Invoke-Wg 'genkey'; $peer=Invoke-Wg 'pubkey' (Invoke-Wg 'genkey')
$conf=Join-Path $script:Data 'Evgenium.conf'
[IO.File]::WriteAllText($conf,"[Interface]`nPrivateKey = $private`nAddress = 192.0.2.253/32`n`n[Peer]`nPublicKey = $peer`nEndpoint = 127.0.0.1:9`nAllowedIPs = 192.0.2.1/32`n")
$private=$null
$p=Start-Process $wg -ArgumentList '/installtunnelservice',('"'+$conf+'"') -Wait -PassThru
if ($p.ExitCode -ne 0) { throw 'Isolated uninstall tunnel setup failed' }
(Get-Service $script:Service).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
$owned=Test-Path $script:RuntimeOwner
$uninstall=Join-Path $app 'unins000.exe'
$p=Start-Process $uninstall -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $Output 'uninstall.log')+'"') -Wait -PassThru
if ($p.ExitCode -ne 0) { throw ('Uninstall exit '+$p.ExitCode) }
Start-Sleep -Seconds 2
if ((Get-Service $script:Service -ErrorAction SilentlyContinue) -or (Test-Path $script:AppRoot) -or (Test-Path $key) -or (Test-Path (Join-Path $app 'Evgenium.exe'))) { throw 'Uninstall left service, keys, registration or executable' }
if ($owned -and (Test-Path $wg)) { throw 'Exclusively owned runtime was not removed' }
if ((Test-Path (Join-Path ([Environment]::GetFolderPath('Programs')) 'Evgenium Network.lnk')) -or (Test-Path (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Evgenium Network.lnk'))) { throw 'Shortcuts remain' }
Write-Output 'Windows Apps uninstall removes own running tunnel, driver, private state and shortcuts: PASS'
