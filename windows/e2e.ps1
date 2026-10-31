# Dedicated disposable Windows runner. No developer workstations.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable GitHub-hosted runner only'}
if(!$env:EVG_WINDOWS_E2E_TOKEN){throw 'Temporary test token missing'}
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim()
$output=Join-Path $env:RUNNER_TEMP 'evgenium-windows'
$setup=Join-Path $output ('Evgenium-Windows-'+$version+'-x64-Setup.exe')
$app=Join-Path $env:ProgramFiles 'EvgeniumNetwork';$exe=Join-Path $app 'Evgenium.exe';$engine=Join-Path $app 'EvgeniumEngine.exe'
if(Test-Path $app){throw 'Existing installation; refuse test'}
$p=Start-Process $setup -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOLAUNCH' -Wait -PassThru;if($p.ExitCode){throw 'E2E setup failed'}
[Reflection.Assembly]::LoadFile($exe) | Out-Null
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest -ExecutableDirectory $app
. (Join-Path $PSScriptRoot 'Policy.ps1')
if(!(Is-Admin)){throw 'Administrator required for disposable E2E'}
$task='Evgenium-CI-Emergency-Disconnect';$armed=$false;$off=$false
$log=Join-Path $output 'network-e2e.log'
function Note([string]$Text){$Text | Tee-Object -FilePath $log -Append | Write-Output}
function Curl([string[]]$More=@()){
 $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
 try{$text=(& curl.exe --noproxy '*' --silent --show-error --max-time 12 @More 2>$null | Out-String).Trim();return @{code=$LASTEXITCODE;text=$text}}finally{$ErrorActionPreference=$old}
}
function Exit-IP { $r=Curl -More @('https://api.ipify.org');if($r.code -ne 0 -or $r.text -notmatch '^\d+\.\d+\.\d+\.\d+$'){throw 'Public IP request failed'};return $r.text }
function Wait-Connected {
 for($i=0;$i -lt 24;$i++){$s=Read-EngineStatus;if($s.state -eq 'connected' -and $s.updated -ge [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-20){return};Start-Sleep -Seconds 2}
 $s=Read-EngineStatus;throw ('VPN never connected: '+$s.message)
}
function Assert-Estonia {if((Exit-IP) -ne '38.180.164.67'){throw 'Wrong full-device egress'} }
function Change-And-Wait([string]$Action,$Request){Change-Policy $Action $Request;Start-Sleep -Seconds 2;Wait-Connected}
$baseline=Exit-IP
$physical=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1
$physicalIP=(Get-NetIPAddress -InterfaceIndex $physical.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1).IPAddress
$beforeDns=@(Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses.Count} | ForEach-Object {"$($_.InterfaceIndex):$($_.AddressFamily):$($_.ServerAddresses -join ',')"} | Sort-Object)
$beforeRoutes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object {"$($_.InterfaceIndex):$($_.NextHop):$($_.RouteMetric)"} | Sort-Object)
try{
 $null=Set-Token $env:EVG_WINDOWS_E2E_TOKEN ('Windows CI '+$env:GITHUB_RUN_ID)
 Remove-Item Env:EVG_WINDOWS_E2E_TOKEN
 # This SYSTEM task survives the runner losing its control channel.
 $action=New-ScheduledTaskAction -Execute $engine -Argument 'uninstall-all'
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
 $null=Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force;$armed=$true
 Note 'Independent SYSTEM rollback armed (5 minutes).'
 $p=Start-Process $exe -ArgumentList '--command','on' -PassThru
 if(!$p.WaitForExit(35000)){$p.Kill();throw 'Packaged connect timed out'}
 if($p.ExitCode){throw ('Packaged connect failed: '+(Read-EngineStatus).message)}
 Wait-Connected;Assert-Estonia
 $discord=Curl -More @('https://discord.com/api/v10/gateway');if($discord.code -ne 0 -or $discord.text -notmatch 'gateway.discord.gg'){throw 'Discord API/DNS failed'}
 $null=Resolve-DnsName github.com -ErrorAction Stop
 Note 'Packaged EXE: full-device Estonia exit, DNS, HTTPS and Discord API PASS.'
 # Loopback must work for browsers, launchers and Codex without a public bypass.
 $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0);$listener.Start();$local=New-Object Net.Sockets.TcpClient
 try{$local.Connect('127.0.0.1',$listener.LocalEndpoint.Port);$accepted=$listener.AcceptTcpClient();$accepted.Close()}finally{$local.Close();$listener.Stop()}
 $bound=Curl -More @('--interface',$physicalIP,'https://api.ipify.org');if($bound.code -eq 0){throw 'Physical bind bypassed protection'}
 Note 'Loopback works; explicit physical-interface egress blocked.'
 # Drop only our own transport child; persistent protection must survive.
 $ours=Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -eq (Join-Path $app 'xray.exe')}
 if(!$ours){throw 'No owned transport child'}
 $ours | ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
 $bound=Curl -More @('--interface',$physicalIP,'https://api.ipify.org');if($bound.code -eq 0){throw 'Traffic escaped during core failure'}
 Start-Sleep -Seconds 4;Wait-Connected;Assert-Estonia
 Note 'Owned core crash: fail-closed and automatic recovery PASS.'
 $curl=(Get-Command curl.exe).Source
 Change-And-Wait 'add' ([pscustomobject]@{category='applications';value=$curl})
 if((Exit-IP) -ne $baseline){throw 'Application exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='applications';value=$curl});Assert-Estonia
 Note 'Application direct exception + removal PASS.'
 Change-And-Wait 'add' ([pscustomobject]@{category='networks';value='=api.ipify.org'})
 if((Exit-IP) -ne $baseline){throw 'Domain exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='networks';value='=api.ipify.org'});Assert-Estonia
 Note 'Domain direct exception + removal PASS.'
 $target=(Resolve-DnsName api.ipify.org -Type A | Where-Object IPAddress | Select-Object -First 1).IPAddress
 Change-And-Wait 'add' ([pscustomobject]@{category='networks';value=($target+'/32')})
 $r=Curl -More @('--resolve',('api.ipify.org:443:'+$target),'https://api.ipify.org');if($r.code -ne 0 -or $r.text -ne $baseline){throw 'IP exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='networks';value=($target+'/32')});Assert-Estonia
 Note 'IP direct exception + removal PASS.'
 Change-And-Wait 'add' ([pscustomobject]@{category='ports';value='tcp:443:out'})
 if((Exit-IP) -ne $baseline){throw 'Outbound port exception failed'}
 $r=Curl -More @('--interface',$physicalIP,'https://api.ipify.org');if($r.code -ne 0 -or $r.text -ne $baseline){throw 'Bound outbound port exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='ports';value='tcp:443:out'});Assert-Estonia
 Note 'Port direct exception (including physical bind) + removal PASS.'
 Change-And-Wait 'add' ([pscustomobject]@{category='dns';value='1.1.1.1'})
 $null=Resolve-DnsName github.com -Server 1.1.1.1 -DnsOnly -ErrorAction Stop
 Change-And-Wait 'remove' ([pscustomobject]@{category='dns';value='1.1.1.1'});Assert-Estonia
 Note 'Explicit direct DNS exception + protected resolver restore PASS.'
 $null=Disconnect-Vpn;$off=$true
 if((Exit-IP) -ne $baseline){throw 'Disconnect did not restore ordinary egress'}
 Note 'Disconnect restored ordinary egress PASS.'
}catch{
 Note ('FAIL: '+$_.Exception.Message)
 $s=Read-EngineStatus;Note ($s | ConvertTo-Json -Depth 6 -Compress)
 # Core log has no credentials/configuration. Keep only bounded recent engine errors.
 $path=Join-Path $script:EngineData 'engine.log';if(Test-Path $path){Get-Content $path -Tail 35 | ForEach-Object {Note $_}}
 throw
}finally{
 Remove-Item Env:EVG_WINDOWS_E2E_TOKEN -ErrorAction SilentlyContinue
 try{$null=Disconnect-Vpn;$off=$true}finally{if($armed -and $off){Unregister-ScheduledTask -TaskName $task -Confirm:$false}}
 if($off){$p=Start-Process (Join-Path $app 'unins000.exe') -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru;if($p.ExitCode){throw 'Final uninstall failed'}}
}
$afterDns=@(Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses.Count} | ForEach-Object {"$($_.InterfaceIndex):$($_.AddressFamily):$($_.ServerAddresses -join ',')"} | Sort-Object)
$afterRoutes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object {"$($_.InterfaceIndex):$($_.NextHop):$($_.RouteMetric)"} | Sort-Object)
if(($beforeDns -join "`n") -cne ($afterDns -join "`n")){throw 'DNS settings not restored'}
if(($beforeRoutes -join "`n") -cne ($afterRoutes -join "`n")){throw 'Default routes not restored'}
if((Get-Service $script:EngineService -ErrorAction SilentlyContinue) -or (Test-Path $script:AppRoot)){throw 'Uninstall left private state or service'}
Note 'Original DNS/routes and complete removal PASS.'
