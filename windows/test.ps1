$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$path=Join-Path $PSScriptRoot 'Evgenium.ps1'
$tree=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
if ($env:OS -eq 'Windows_NT') {
    . $path -Command selftest
    if ($global:EvgeniumExitCode -ne 0) { throw 'Self-test failed' }
} else {
    # Portable contract checks only; this does not test Windows networking or DPAPI.
    $tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | ForEach-Object { Invoke-Expression $_.Extent.Text }
    $script:Version='0.2.0'; Self-Test
}
function Reject($Block) { $caught=$false; try { & $Block } catch { $caught=$true }; if (!$caught) { throw 'Expected rejection' } }
$good=[pscustomobject]@{schema=1;public_key='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';endpoint='195.209.211.163:51820';address='10.78.0.2/32';dns=@('1.1.1.1','1.0.0.1');mtu=1280;allowed_ips=@('0.0.0.0/0','::/0')}
foreach ($entry in @(@('endpoint',"evil`nPostUp = cmd.exe"),@('address','10.78.0.2/32, 1.2.3.4/0'),@('public_key',"bad`nPrivateKey = secret"),@('mtu',1000),@('dns',@('8.8.8.8')),@('allowed_ips',@('0.0.0.0/1','128.0.0.0/1')))) {
    $bad=$good.PSObject.Copy(); $bad.($entry[0])=$entry[1]
    Reject { Validate-Profile $bad }
}
$fake=[pscustomobject]@{schema=1;version='0.2.1';installer_size=1000000;installer_sha256=('a'*64);installer_url='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/windows-v0.2.1/Evgenium-Windows-0.2.1-x64-Setup.exe'}
foreach ($entry in @(@('version','../../evil'),@('version','0.2.1;calc'),@('installer_url','https://evil.example/a.exe'),@('installer_sha256','abc'),@('installer_size',0),@('installer_size',40000000))) { $bad=$fake.PSObject.Copy(); $bad.($entry[0])=$entry[1]; Reject { Validate-Manifest $bad } }
Validate-Manifest $fake
$secret='test-roundtrip-not-a-real-token'
if ($env:OS -eq 'Windows_NT') { if ((Unseal (Seal $secret)) -cne $secret) { throw 'DPAPI roundtrip failed' } } else { Write-Output 'DPAPI test SKIPPED: not Windows' }
# Reparse points must not let uninstall follow a link outside its own state.
if ($env:OS -eq 'Windows_NT') {
 $temporary=Join-Path ([IO.Path]::GetTempPath()) ('evgenium-test-'+[Guid]::NewGuid().ToString('N'))
 $null=New-Item -ItemType Directory -Path $temporary
 try {
  $aclTest=Join-Path $temporary 'private'; Protect-Directory $aclTest
  $permissions=Get-Acl -LiteralPath $aclTest
  if (!$permissions.AreAccessRulesProtected) { throw 'Private ACL inherits access' }
  $target=Join-Path $temporary 'outside'; $null=New-Item -ItemType Directory -Path $target
  $tree=Join-Path $temporary 'tree'; $null=New-Item -ItemType Directory -Path $tree
  $link=Join-Path $tree 'junction'; $null=New-Item -ItemType Junction -Path $link -Target $target
  Reject { Assert-SafeTree $tree }
  [IO.Directory]::Delete($link)
  Assert-SafeTree $tree
 } finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
Write-Output 'Windows profile/manifest injection rejection, DPAPI/ACL and safe-uninstall traversal tests passed.'
