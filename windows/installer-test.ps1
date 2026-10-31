param([string]$Output)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted runner only'}
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw -Encoding UTF8).Trim();$package=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64')
[Reflection.Assembly]::LoadFile((Join-Path $package 'Evgenium.exe')) | Out-Null
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest -ExecutableDirectory $package
. (Join-Path $PSScriptRoot 'Policy.ps1')
$app=Join-Path $env:ProgramFiles 'EvgeniumNetwork';$key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{53E2495A-A134-40DC-BA91-D2FD582DE3AD}_is1'
if((Test-Path $app) -or (Test-Path $script:AppRoot)){throw 'Previous installation; refuse destructive test'}
$state=Read-State;$state.token=Seal ('EVN1-'+('a'*43));Save-State $state;$before=(Get-FileHash $script:StatePath).Hash
function Install-Version([string]$Path,[string]$Version){
 $p=Start-Process $Path -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOLAUNCH',('/LOG="'+(Join-Path $Output ('install-'+$Version+'.log'))+'"') -Wait -PassThru
 if($p.ExitCode -ne 0){throw ('Setup failed '+$p.ExitCode)}
 if((Get-ItemProperty $key).DisplayVersion -ne $Version){throw 'Windows Apps registration'}
 if((Get-FileHash $script:StatePath).Hash -cne $before){throw 'Update lost token/device identity'}
 if(Test-Path (Join-Path $app 'EvgeniumCLI.exe')){throw 'Public CLI installed'}
 foreach($file in @('Evgenium.exe','Evgenium.exe.config','EvgeniumEngine.exe','xray.exe','wintun.dll','unins000.exe')){if(!(Test-Path (Join-Path $app $file))){throw ('Missing '+$file)}}
}
$setup=Join-Path $Output ('Evgenium-Windows-'+$version+'-x64-Setup.exe');Install-Version $setup $version;Install-Version $setup $version
$fixture=Join-Path $Output 'upgrade-fixture';& (Join-Path $PSScriptRoot 'build.ps1') -Output $fixture -TestVersion '0.2.1'
Install-Version (Join-Path $fixture 'Evgenium-Windows-0.2.1-x64-Setup.exe') '0.2.1'
$p=Start-Process $setup -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOLAUNCH' -Wait -PassThru
if($p.ExitCode -eq 0 -or (Get-ItemProperty $key).DisplayVersion -ne '0.2.1'){throw 'Downgrade not rejected'}
Write-Output 'Fresh setup, repair, real newer EXE upgrade, token preservation and downgrade rejection: PASS'
$p=Start-Process (Join-Path $app 'unins000.exe') -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $Output 'uninstall.log')+'"') -Wait -PassThru
if($p.ExitCode -ne 0){throw ('Uninstall failed '+$p.ExitCode)};Start-Sleep -Seconds 2
if((Test-Path $script:AppRoot) -or (Test-Path $key) -or (Test-Path (Join-Path $app 'Evgenium.exe')) -or (Get-Service $script:EngineService -ErrorAction SilentlyContinue)){throw 'Uninstall remnants'}
foreach($folder in @('CommonPrograms','CommonDesktopDirectory')){if(Test-Path (Join-Path ([Environment]::GetFolderPath($folder)) 'Evgenium Network.lnk')){throw 'Shortcut remains'}}
Write-Output 'Windows Apps complete removal: no token, keys, service, application or shortcuts: PASS'
