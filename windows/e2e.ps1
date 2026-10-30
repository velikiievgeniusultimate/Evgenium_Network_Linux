# Dedicated disposable Windows GitHub runner only. Temporary account only.
# Never run against a developer workstation: this test enables a full tunnel.
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'E2E requires a dedicated GitHub-hosted runner' }
if (!$env:EVG_WINDOWS_E2E_TOKEN) { throw 'Temporary E2E token was not supplied' }
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest
if ($global:EvgeniumExitCode -ne 0) { throw 'Self-test failed' }
if (!(Is-Admin)) { throw 'Hosted E2E requires its administrator account' }
if (Get-Service -Name $script:Service -ErrorAction SilentlyContinue) { throw 'Existing Evgenium tunnel: test refused' }
$taskName='Evgenium-CI-Emergency-Disconnect'
$working=Join-Path ([IO.Path]::GetTempPath()) ('evgenium-e2e-'+[Guid]::NewGuid().ToString('N'))
$script:AppRoot=$working; $script:Data=Join-Path $working 'private'; $script:StatePath=Join-Path $script:Data 'state.json'
$beforeDns=@(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count } | ForEach-Object { ($_.InterfaceIndex.ToString()+':'+$_.AddressFamily+':'+($_.ServerAddresses -join ',')) } | Sort-Object)
$beforeRoutes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object { $_.InterfaceIndex.ToString()+':'+$_.NextHop+':'+$_.RouteMetric } | Sort-Object)
$armed=$false; $confirmedOff=$false
try {
    Protect-Directory $script:Data
    $wg=Ensure-WireGuard
    $null=Set-Token $env:EVG_WINDOWS_E2E_TOKEN ('GitHub Windows E2E '+$env:GITHUB_RUN_ID)
    Remove-Item Env:EVG_WINDOWS_E2E_TOKEN
    $action=New-ScheduledTaskAction -Execute $wg -Argument '/uninstalltunnelservice Evgenium'
    $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(180)
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
    $null=Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force
    $armed=$true
    Write-Output 'Independent SYSTEM rollback armed for 180 seconds (own Evgenium tunnel only).'
    $result=Connect-Vpn
    if (!(Tunnel-Running) -or !(Validate-Connection)) { throw 'Real Windows full tunnel did not confirm Estonia' }
    Write-Output 'Real Windows data plane: Estonia exit 38.180.164.67, HTTPS and Discord/DNS PASS.'
} finally {
    Remove-Item Env:EVG_WINDOWS_E2E_TOKEN -ErrorAction SilentlyContinue
    try {
        $null=Disconnect-Vpn
        if (Get-Service -Name $script:Service -ErrorAction SilentlyContinue) { throw 'Tunnel service remains installed' }
        $confirmedOff=$true
    } finally {
        # Never disarm the independent safety net while the tunnel may still exist.
        if ($armed -and $confirmedOff) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
        if ($confirmedOff -and (Test-Path -LiteralPath $working)) { Remove-Item -LiteralPath $working -Recurse -Force }
    }
}
Start-Sleep -Seconds 2
$afterDns=@(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count } | ForEach-Object { ($_.InterfaceIndex.ToString()+':'+$_.AddressFamily+':'+($_.ServerAddresses -join ',')) } | Sort-Object)
$afterRoutes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object { $_.InterfaceIndex.ToString()+':'+$_.NextHop+':'+$_.RouteMetric } | Sort-Object)
if (($beforeDns -join "`n") -cne ($afterDns -join "`n")) { throw 'DNS did not return to its original settings' }
if (($beforeRoutes -join "`n") -cne ($afterRoutes -join "`n")) { throw 'Default routes did not return to their original settings' }
$null=Resolve-DnsName 'github.com' -ErrorAction Stop
Write-Output 'Own tunnel removed, original DNS/default routes restored, ordinary DNS works: PASS.'
