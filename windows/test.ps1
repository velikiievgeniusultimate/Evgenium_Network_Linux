param([string]$Package)
$ErrorActionPreference='Stop'
foreach($file in Get-ChildItem $PSScriptRoot -Filter '*.ps1'){$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$t,[ref]$e);if($e.Count){throw ($e | Out-String)}}
if($env:OS -ne 'Windows_NT'){Write-Output 'PowerShell syntax PASS; Windows networking/DPAPI not tested on Linux.';return}
[Reflection.Assembly]::LoadFile((Join-Path $Package 'Evgenium.exe')) | Out-Null
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest -ExecutableDirectory $Package
. (Join-Path $PSScriptRoot 'Policy.ps1')
function Reject($Block){$caught=$false;try{& $Block}catch{$caught=$true};if(!$caught){throw 'Expected rejection'}}
Self-Test
$good=[pscustomobject]@{schema=2;version='0.2.0';installer_url='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/windows-v0.2.0/Evgenium-Windows-0.2.0-x64-Setup.exe';installer_sha256=('a'*64);installer_size=1000000}
Validate-Manifest $good
foreach($entry in @(@('version','../../evil'),@('version','0.2.0;calc'),@('installer_url','https://evil.test/update.exe'),@('installer_sha256','abc'),@('installer_size',0),@('installer_size',200000000))){$bad=$good.PSObject.Copy();$bad.($entry[0])=$entry[1];Reject{Validate-Manifest $bad}}
$temp=Join-Path $env:RUNNER_TEMP ('evg-unit-'+[Guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $temp
try{
 $path=Join-Path $temp 'setup.exe';[IO.File]::WriteAllBytes($path,(New-Object byte[] 100000));$manifest=$good.PSObject.Copy();$manifest.installer_size=100000;$manifest.installer_sha256=(Get-FileHash $path).Hash.ToLowerInvariant();Assert-Installer $path $manifest;[IO.File]::AppendAllText($path,'tampered');Reject{Assert-Installer $path $manifest}
 $private=Join-Path $temp 'private';Protect-Directory $private;$acl=Get-Acl $private;if(!$acl.AreAccessRulesProtected){throw 'ACL inherits'}
 foreach($rule in $acl.Access){$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($sid -notin @($script:Sid,'S-1-5-18','S-1-5-32-544')){throw 'Unexpected ACL principal'}}
 $outside=Join-Path $temp 'outside';$tree=Join-Path $temp 'tree';$null=New-Item -ItemType Directory $outside;$null=New-Item -ItemType Directory $tree;$link=Join-Path $tree 'junction';$null=New-Item -ItemType Junction -Path $link -Target $outside;Reject{Assert-SafeTree $tree};[IO.Directory]::Delete($link)
 $secret='unit-test-not-a-real-token';if((Unseal (Seal $secret)) -cne $secret){throw 'DPAPI roundtrip'}
 $savedData=$script:Data;$savedStatePath=$script:StatePath
 try{$script:Data=$private;$script:StatePath=Join-Path $private 'unicode-state.json';$state=Read-State;$state.name='Устройство — Проверка ё';Save-State $state;if((Read-State).name -cne $state.name){throw 'UTF-8 device name did not survive restart'}}finally{$script:Data=$savedData;$script:StatePath=$savedStatePath}
 $key=Invoke-Engine 'keygen' | ConvertFrom-Json;if(!(Check-Key $key.private_key) -or !(Check-Key $key.public_key)){throw 'Key generation'};if((Invoke-Engine 'pubkey' $key.private_key) -cne $key.public_key){throw 'Key pipe roundtrip'};$key=$null
 foreach($pair in @(@('applications',"bad.exe`nmalicious"),@('networks','0.0.0.0/0'),@('networks','https://example.com/x'),@('ports','udp:53:out'),@('dns','127.0.0.1'))){Reject{Normalize-Exception $pair[0] $pair[1]}}
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
Write-Output 'GUI package, strict update validation, DPAPI, ACL, private key pipes and safe uninstall traversal: PASS'
