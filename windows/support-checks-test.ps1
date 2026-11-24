[CmdletBinding()]
param([switch]$RequireWindows11)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SupportChecks.ps1')
$os=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($RequireWindows11 -and ([int]$os.CurrentBuildNumber -lt 22000 -or $os.InstallationType -ne 'Client')){
    throw 'This run requires Windows 11 desktop.'
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('Evgenium-QA-'+[Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$previous=$env:OneDrive
try{
    $plain=Test-EvgSupportFile $root
    if($plain.status -ne 'ok' -or $plain.kind -ne 'local' -or !$plain.cleanup_ok -or @(Get-ChildItem -LiteralPath $root -Force).Count){throw "Local save/rename/read/delete failed: $($plain | ConvertTo-Json -Compress)"}
    $shell=Test-EvgSupportShell $root
    if($shell.status -ne 'ok'){throw "Windows Shell could not open a local directory: $($shell | ConvertTo-Json -Compress)"}
    $absent=Test-EvgSupportFile (Join-Path $root 'absent')
    if($absent.status -ne 'missing'){throw 'Missing directory not distinguished'}
    $network=Test-EvgSupportFile '\\evgenium-qa.invalid\diagnostic'
    if($network.kind -ne 'network' -or $network.status -ne 'read_only'){throw 'A network share must not be written'}
    $env:OneDrive=$root
    $cloud=Test-EvgSupportFile $root
    if($cloud.kind -ne 'cloud' -or $cloud.status -ne 'read_only' -or @(Get-ChildItem -LiteralPath $root -Force).Count){throw 'A cloud folder must not be written'}
    $env:OneDrive=$previous
    $deny=Join-Path $root 'denied';$null=[IO.Directory]::CreateDirectory($deny)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $null=& icacls.exe $deny /deny ("*"+$sid+':(WD,AD)')
    if($LASTEXITCODE -ne 0){throw 'Could not set test folder ACL'}
    try{
        $blocked=Test-EvgSupportFile $deny
        if($blocked.status -ne 'denied' -or $blocked.step -ne 'mkdir'){throw "Write deny not detected: $($blocked | ConvertTo-Json -Compress)"}
    }finally{
        $null=& icacls.exe $deny /remove:d ("*"+$sid)
    }
    $support=@{}
    foreach($task in @(Get-EvgSupportPlan)){$support[$task.id]=Invoke-EvgSupportCheck $task.id}
    $report=$support | ConvertTo-Json -Compress -Depth 6
    if($report -match '(?i)[a-z]:\\|\\\\|S-1-5-21|EVN1-'){throw 'Support output leaked a path or identifier'}
    Write-Output "PASS Windows build $($os.CurrentBuildNumber) $($os.InstallationType) x64=$([Environment]::Is64BitProcess)"
    Write-Output 'PASS create, write, rename, read, delete, Shell enumeration, ACL deny, cloud/network no writes'
    Write-Output $report
}finally{
    $env:OneDrive=$previous
    [IO.Directory]::Delete($root,$true)
}
