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
    $script:Version='0.1.0'; Self-Test
}
function Reject($Block) { $caught=$false; try { & $Block } catch { $caught=$true }; if (!$caught) { throw 'Expected rejection' } }
$good=[pscustomobject]@{schema=1;public_key='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';endpoint='195.209.211.163:51820';address='10.78.0.2/32';dns=@('1.1.1.1','1.0.0.1');mtu=1280;allowed_ips=@('0.0.0.0/0','::/0')}
foreach ($entry in @(@('endpoint',"evil`nPostUp = cmd.exe"),@('address','10.78.0.2/32, 1.2.3.4/0'),@('public_key',"bad`nPrivateKey = secret"),@('mtu',1000),@('dns',@('8.8.8.8')),@('allowed_ips',@('0.0.0.0/1','128.0.0.0/1')))) {
    $bad=$good.PSObject.Copy(); $bad.($entry[0])=$entry[1]
    Reject { Validate-Profile $bad }
}
$fake=[pscustomobject]@{schema=1;version='0.1.1';sha256=('a'*64);url='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/windows-v0.1.1/Evgenium-Windows-0.1.1-x64.zip'}
foreach ($entry in @(@('version','../../evil'),@('version','0.1.1;calc'),@('url','https://evil.example/a.zip'),@('sha256','abc'))) { $bad=$fake.PSObject.Copy(); $bad.($entry[0])=$entry[1]; Reject { Validate-Manifest $bad } }
$secret='test-roundtrip-not-a-real-token'
if ($env:OS -eq 'Windows_NT') { if ((Unseal (Seal $secret)) -cne $secret) { throw 'DPAPI roundtrip failed' } } else { Write-Output 'DPAPI test SKIPPED: not Windows' }
# No live token, administrator rights or network needed for archive rejection tests.
Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('evgenium-test-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temporary
try {
    foreach ($unsafe in @('../Evgenium.exe','sub/Evgenium.exe','Evgenium.exe:ads','EVGENIUM.exe')) {
        $zipPath=Join-Path $temporary ([Guid]::NewGuid().ToString('N')+'.zip')
        $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
        try { foreach ($file in @($unsafe,'EvgeniumCLI.exe','README.txt','VERSION')) { $null=$zip.CreateEntry($file) } } finally { $zip.Dispose() }
        Reject { Expand-VerifiedArchive $zipPath (Join-Path $temporary ([Guid]::NewGuid().ToString('N'))) }
    }
    $zipPath=Join-Path $temporary 'valid.zip'
    $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
    try { foreach ($file in @('Evgenium.exe','EvgeniumCLI.exe','README.txt','VERSION')) { $null=$zip.CreateEntry($file) } } finally { $zip.Dispose() }
    $output=Join-Path $temporary 'valid'; Expand-VerifiedArchive $zipPath $output
    if ((Get-ChildItem -LiteralPath $output).Count -ne 4) { throw 'Valid archive extraction failed' }
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
Write-Output 'Windows contract, injection rejection, archive traversal tests passed (DPAPI on Windows only).'
