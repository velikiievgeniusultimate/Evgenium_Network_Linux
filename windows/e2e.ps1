# Dedicated disposable Windows runner. No developer workstations.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable GitHub-hosted runner only'}
if(!$env:EVG_WINDOWS_E2E_TOKEN){throw 'Temporary test token missing'}
$version=(Get-Content (Join-Path $PSScriptRoot 'VERSION') -Raw -Encoding UTF8).Trim()
$output=Join-Path $env:RUNNER_TEMP 'evgenium-windows'
$setup=Join-Path $output ('Evgenium-Windows-'+$version+'-x64-Setup.exe')
$app=Join-Path $env:ProgramFiles 'EvgeniumNetwork';$exe=Join-Path $app 'Evgenium.exe';$engine=Join-Path $app 'EvgeniumEngine.exe'
if(Test-Path $app){throw 'Existing installation; refuse test'}
$p=Start-Process $setup -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOLAUNCH' -Wait -PassThru;if($p.ExitCode){throw 'E2E setup failed'}
# Keep the test harness assembly separate: loading the installed EXE would
# lock it in powershell.exe and create an artificial installer failure.
[Reflection.Assembly]::LoadFile((Join-Path $output ('Evgenium-Windows-'+$version+'-x64/Evgenium.exe'))) | Out-Null
. (Join-Path $PSScriptRoot 'Evgenium.ps1') -Command selftest -ExecutableDirectory $app
. (Join-Path $PSScriptRoot 'Policy.ps1')
. (Join-Path $PSScriptRoot 'Reports.ps1')
if(!(Is-Admin)){throw 'Administrator required for disposable E2E'}
$task='Evgenium-CI-Emergency-Disconnect';$armed=$false;$off=$false
$log=Join-Path $output 'network-e2e.log'
function Note([string]$Text){[IO.File]::AppendAllText($log,$Text+"`n",(New-Object Text.UTF8Encoding($false)));Write-Output $Text}
function Probe-Http([string[]]$More=@()){
 $old=$ErrorActionPreference;$ErrorActionPreference='Continue'
 try{$text=(& curl.exe -4 --noproxy '*' --silent --show-error --max-time 12 @More 2>$null | Out-String).Trim();return @{code=$LASTEXITCODE;text=$text}}finally{$ErrorActionPreference=$old}
}
function Exit-IP([switch]$PrimaryOnly) {
 # A single external IP service can stall while the VPN and other services work.
 # Never ignore a valid but wrong IP: callers must still fail on any real leak.
 $addresses=@('https://api.ipify.org')
 if(!$PrimaryOnly){$addresses+= 'https://www.cloudflare.com/cdn-cgi/trace'}
 for($attempt=0;$attempt -lt 2;$attempt++){
  foreach($address in $addresses){
   $r=Probe-Http -More @($address)
   if($r.code -eq 0){
    if($r.text -match '^\d+\.\d+\.\d+\.\d+$'){return $r.text}
    if($r.text -match '(?m)^ip=(\d+\.\d+\.\d+\.\d+)\r?$'){return $Matches[1]}
   }
   Note ('Public IP endpoint unavailable: '+$address+' curl='+$r.code)
  }
  Start-Sleep -Seconds 1
 }
 throw 'No independent public IP endpoint replied'
}
function Wait-Connected {
 $expected=(Get-Content -LiteralPath (Join-Path $script:EngineData 'engine.json') -Raw | ConvertFrom-Json).revision
 for($i=0;$i -lt 24;$i++){$s=Read-EngineStatus;if($s.state -eq 'connected' -and $s.config_revision -eq $expected -and $s.updated -ge [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-20){return};Start-Sleep -Seconds 2}
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
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
 $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
 $null=Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force;$armed=$true
 Note 'Independent SYSTEM rollback armed (10 minutes).'
 $p=Start-Process $exe -ArgumentList '--command','on' -PassThru
 if(!$p.WaitForExit(35000)){$p.Kill();throw 'Packaged connect timed out'}
 if($p.ExitCode){throw ('Packaged connect failed: '+(Read-EngineStatus).message)}
 Wait-Connected;Assert-Estonia
 $discordOk=$false
 for($i=0;$i -lt 3;$i++){$discord=Probe-Http -More @('https://discord.com/api/v10/gateway');if($discord.code -eq 0 -and $discord.text -match 'gateway.discord.gg'){$discordOk=$true;break};Start-Sleep -Seconds 2}
 if(!$discordOk){throw 'Discord API/DNS failed after bounded retries'}
 $null=Resolve-DnsName github.com -ErrorAction Stop
 Note 'Packaged EXE: full-device Estonia exit, DNS, HTTPS and Discord API PASS.'
 # Loopback must work for browsers, launchers and Codex without a public bypass.
 $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0);$listener.Start();$local=New-Object Net.Sockets.TcpClient
 try{$local.Connect('127.0.0.1',$listener.LocalEndpoint.Port);$accepted=$listener.AcceptTcpClient();$accepted.Close()}finally{$local.Close();$listener.Stop()}
 $bound=Probe-Http -More @('--interface',$physicalIP,'https://api.ipify.org');if($bound.code -eq 0){throw 'Physical bind bypassed protection'}
 Note 'Loopback works; explicit physical-interface egress blocked.'
 # Drop only our own transport child; persistent protection must survive.
 $ours=Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -eq (Join-Path $app 'xray.exe')}
 if(!$ours){throw 'No owned transport child'}
 $ours | ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
 $bound=Probe-Http -More @('--interface',$physicalIP,'https://api.ipify.org');if($bound.code -eq 0){throw 'Traffic escaped during core failure'}
 Start-Sleep -Seconds 4;Wait-Connected;Assert-Estonia
 Note 'Owned core crash: fail-closed and automatic recovery PASS.'
 $curl=(Get-Command curl.exe).Source
 Change-And-Wait 'add' ([pscustomobject]@{category='applications';value=$curl})
 if((Exit-IP) -ne $baseline){throw 'Application exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='applications';value=$curl});Assert-Estonia
 Note 'Application direct exception + removal PASS.'
 # A process-name fixture exercises the same Windows TUN lookup used for the
 # emulator, without pretending this runner has BlueStacks or Mobile Legends.
 $split=Join-Path $output 'split-egress';$null=New-Item -ItemType Directory -Force $split
 $bluePlayer=Join-Path $split 'HD-Player.exe';Copy-Item $curl $bluePlayer
 $blueAgent=Join-Path $split 'HD-Agent.exe';$ordinaryUdp=Join-Path $split 'ordinary-udp.exe'
 $compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
 & $compiler /nologo /optimize+ /platform:x64 ('/out:'+$blueAgent) (Join-Path $PSScriptRoot 'russia-udp-test.cs')
 if($LASTEXITCODE){throw 'UDP process fixture compilation failed'};Copy-Item $blueAgent $ordinaryUdp
 Change-And-Wait 'bluestacks-russia' ([pscustomobject]@{enabled=$true})
 $r=(& $bluePlayer --noproxy '*' --silent --show-error --max-time 12 'https://api.ipify.org' | Out-String).Trim()
 if($LASTEXITCODE -ne 0 -or $r -ne '195.209.211.163'){throw 'BlueStacks-named process did not use Russian TCP exit'}
 $r=(& $blueAgent | Out-String).Trim();if($LASTEXITCODE -ne 0 -or $r -ne '195.209.211.163'){throw 'BlueStacks-named process did not use Russian UDP exit'}
 Assert-Estonia
 $r=(& $ordinaryUdp | Out-String).Trim();if($LASTEXITCODE -ne 0 -or $r -ne '38.180.164.67'){throw 'Unrelated UDP process left Estonia'}
 $discord=Probe-Http -More @('https://discord.com/api/v10/gateway');if($discord.code -ne 0 -or $discord.text -notmatch 'gateway.discord.gg'){throw 'Discord failed during split egress'}
 Note 'BlueStacks-named fixtures: TCP/UDP Russia; unrelated TCP/UDP and Discord Estonia PASS. Real emulator/game not tested.'
 $coreBefore=(Get-Process xray | Select-Object -First 1).Id
 $holdListener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0);$holdListener.Start();$holdProcess=$null
 try{
  $holdPort=$holdListener.LocalEndpoint.Port
  $holdProcess=Start-Process $bluePlayer -ArgumentList '--noproxy','*','--silent','--max-time','50',('http://127.0.0.1:'+$holdPort+'/') -PassThru
  Start-Sleep -Seconds 34
  if($holdProcess.HasExited){throw 'Named fixture did not remain alive for process discovery'}
  if((Get-Process xray | Select-Object -First 1).Id -ne $coreBefore){throw 'Application discovery restarted the VPN core'}
  Assert-Estonia
  Note 'New named process discovered without restarting TUN/core PASS.'
 }finally{
  if($holdProcess -and !$holdProcess.HasExited){$holdProcess.Kill()}
  $holdListener.Stop()
 }

 # Conflict rules must not permit physical egress or override the Russia rule.
 Change-And-Wait 'add' ([pscustomobject]@{category='applications';value=$bluePlayer})
 Change-And-Wait 'add' ([pscustomobject]@{category='ports';value='tcp:443:out'})
 $r=(& $bluePlayer --noproxy '*' --silent --show-error --max-time 12 'https://api.ipify.org' | Out-String).Trim()
 if($LASTEXITCODE -ne 0 -or $r -ne '195.209.211.163'){throw 'Direct exception overrode Russia policy'}
 $oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
 try{& $bluePlayer --noproxy '*' --interface $physicalIP --silent --max-time 5 'https://api.ipify.org' 2>$null | Out-Null;$escaped=$LASTEXITCODE -eq 0}finally{$ErrorActionPreference=$oldPreference}
 if($escaped){throw 'Russia-selected process escaped via physical bind'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='ports';value='tcp:443:out'})
 Change-And-Wait 'remove' ([pscustomobject]@{category='applications';value=$bluePlayer})
 Change-And-Wait 'bluestacks-russia' ([pscustomobject]@{enabled=$false});Assert-Estonia
 $r=(& $bluePlayer --noproxy '*' --silent --show-error --max-time 12 'https://api.ipify.org' | Out-String).Trim()
 if($LASTEXITCODE -ne 0 -or $r -ne '38.180.164.67'){throw 'Disabling split egress did not restore Estonia'}
 Note 'Russia priority, physical-bind protection and disabling restores Estonia PASS.'
 Change-And-Wait 'add' ([pscustomobject]@{category='networks';value='=api.ipify.org'})
 if((Exit-IP -PrimaryOnly) -ne $baseline){throw 'Domain exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='networks';value='=api.ipify.org'});Assert-Estonia
 Note 'Domain direct exception + removal PASS.'
 $target=(Resolve-DnsName api.ipify.org -Type A | Where-Object IPAddress | Select-Object -First 1).IPAddress
 Change-And-Wait 'add' ([pscustomobject]@{category='networks';value=($target+'/32')})
 $r=Probe-Http -More @('--resolve',('api.ipify.org:443:'+$target),'https://api.ipify.org');if($r.code -ne 0 -or $r.text -ne $baseline){throw 'IP exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='networks';value=($target+'/32')});Assert-Estonia
 Note 'IP direct exception + removal PASS.'
 Change-And-Wait 'add' ([pscustomobject]@{category='ports';value='tcp:443:out'})
 if((Exit-IP) -ne $baseline){throw 'Outbound port exception failed'}
 $r=Probe-Http -More @('--interface',$physicalIP,'https://api.ipify.org');if($r.code -ne 0 -or $r.text -ne $baseline){throw 'Bound outbound port exception failed'}
 Change-And-Wait 'remove' ([pscustomobject]@{category='ports';value='tcp:443:out'});Assert-Estonia
 Note 'Port direct exception (including physical bind) + removal PASS.'
 Change-And-Wait 'add' ([pscustomobject]@{category='dns';value='1.1.1.1'})
 $null=Resolve-DnsName github.com -Server 1.1.1.1 -DnsOnly -ErrorAction Stop
 Change-And-Wait 'remove' ([pscustomobject]@{category='dns';value='1.1.1.1'});Assert-Estonia
 Note 'Explicit direct DNS exception + protected resolver restore PASS.'
 # Local DNS toggle must change its actual WFP behavior, without blocking
 # unrelated loopback IPC or sending local queries to a public resolver.
 $dnsSocket=New-Object Net.Sockets.UdpClient((New-Object Net.IPEndPoint([Net.IPAddress]::Loopback,53)))
 $dnsSocket.Client.ReceiveTimeout=700
 function Local-DNS-Probe {
  $sender=New-Object Net.Sockets.UdpClient
  try{try{$null=$sender.Send([byte[]](1,2,3,4),4,'127.0.0.1',53)}catch{}
   $peer=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
   try{$packet=$dnsSocket.Receive([ref]$peer);return $packet.Length -eq 4}catch{return $false}
  }finally{$sender.Close()}
 }
 try{
  if(!(Local-DNS-Probe)){throw 'Default local DNS exception unavailable'}
  Change-And-Wait 'base' ([pscustomobject]@{value='dns:stub';enabled=$false})
  if(Local-DNS-Probe){throw 'Disabled local DNS base rule still bypassed VPN'}
  Change-And-Wait 'base' ([pscustomobject]@{value='dns:stub';enabled=$true})
  if(!(Local-DNS-Probe)){throw 'Re-enabled local DNS base rule unavailable'}
  Assert-Estonia;Note 'Local DNS base toggle + restore PASS.'
 }finally{$dnsSocket.Close()}
 # Test real alternate carriers and health-triggered fallback, not just scores.
 foreach($id in @('ru-tcp','ru-xhttp')){Change-And-Wait 'route' ([pscustomobject]@{value=$id});Assert-Estonia;Note ('Fixed route '+$id+' PASS.')}
 Change-And-Wait 'route' ([pscustomobject]@{value='auto'});Assert-Estonia
 $initialStatus=Read-EngineStatus
 $savedOrder=@($initialStatus.ranking | ForEach-Object {$_.id}) -join ','
 $oldRoute=$initialStatus.route
 if($oldRoute -ne $initialStatus.ranking[0].id){throw 'Automatic start did not use saved leader'}
 $rule='Evgenium-CI-Drop-Selected-Carrier'
 try{
  if($oldRoute -eq 'ru-wg'){$program=$engine;$protocol='UDP';$port=51820}else{$program=Join-Path $app 'xray.exe';$protocol='TCP';$port=if($oldRoute -eq 'ru-tcp'){24580}else{24581}}
  $null=New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Outbound -Action Block -Program $program -Protocol $protocol -RemoteAddress 195.209.211.163 -RemotePort $port
  $switched=$false
  for($i=0;$i -lt 32;$i++){Start-Sleep -Seconds 2;$s=Read-EngineStatus;if($s.state -eq 'connected' -and $s.route -ne $oldRoute){$switched=$true;break}}
  if(!$switched){throw 'Automatic carrier fallback failed'};Assert-Estonia
  Note ('Blocked '+$oldRoute+' -> automatic '+$s.route+' fallback PASS.')
 }finally{Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue}
 if((@((Read-EngineStatus).ranking | ForEach-Object {$_.id}) -join ',') -ne $savedOrder){throw 'Failover changed saved route order'}
 Change-And-Wait 'route' ([pscustomobject]@{value='auto'});Assert-Estonia
 if((Read-EngineStatus).route -ne $oldRoute){throw 'New automatic connection did not return to leader'}
 if((@((Read-EngineStatus).ranking | ForEach-Object {$_.id}) -join ',') -ne $savedOrder){throw 'Reconnect remeasured or changed order'}
 Note 'Saved order survives failover; new connection returns to leader PASS.'
 # Explicit user-authorized CI diagnostic account, no real user's report.
 $report=Create-Report
 if(@($report.checks.routes | Where-Object good).Count -lt 2){throw 'Fewer than two working carriers'}
 foreach($route in $report.checks.routes){Note ('Carrier: '+$route.id+' good='+$route.good+' Mbps='+$route.download_mbps)}
 $id=Send-Report $report;Note ('UDP/DNS/service diagnostic upload acknowledged: '+$id)
 Assert-Estonia
 $stateHash=(Get-FileHash $script:StatePath).Hash
 $v=[version]$version;$newer=('{0}.{1}.{2}' -f $v.Major,$v.Minor,($v.Build+1));$fixture=Join-Path $output ('upgrade-fixture/Evgenium-Windows-'+$newer+'-x64-Setup.exe')
 $p=Start-Process $fixture -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOLAUNCH',('/LOG="'+(Join-Path $output 'active-upgrade.log')+'"') -Wait -PassThru
 if($p.ExitCode){throw ('Active VPN upgrade failed: '+$p.ExitCode)}
 Start-Sleep -Seconds 3;Wait-Connected;Assert-Estonia
 if((Get-FileHash $script:StatePath).Hash -cne $stateHash){throw 'Active update changed token/key/device'}
 Note 'Active VPN update: token preserved, tunnel resumed, Estonia exit PASS.'
 $null=Disconnect-Vpn;$off=$true
 if((Exit-IP) -ne $baseline){throw 'Disconnect did not restore ordinary egress'}
 Note 'Disconnect restored ordinary egress PASS.'
}catch{
 Note ('FAIL: '+$_.Exception.Message)
 $s=Read-EngineStatus;Note ($s | ConvertTo-Json -Depth 6 -Compress)
 # Core log has no credentials/configuration. Keep only bounded recent engine errors.
 $path=Join-Path $script:EngineData 'engine.log';if(Test-Path $path){Get-Content $path -Tail 35 -Encoding UTF8 | ForEach-Object {Note $_}}
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
