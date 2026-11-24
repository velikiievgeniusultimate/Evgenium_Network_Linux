function Create-Report([switch]$Full,[scriptblock]$Progress) {
    $extras=$null;$network='ok'
    $checks=@{routes=@();transfers=@();packets=@{};services=@()}
    $before=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
    $exe=Join-Path $ExecutableDirectory 'EvgeniumEngine.exe'
    $gui=Join-Path $ExecutableDirectory 'Evgenium.exe'
    $pump=$null
    if($Progress){$pump=[Action]{[EvgeniumDesktop]::PumpEvents()}}
    if($Full) {
        $plan=@(Get-EvgSupportPlan);$step=0;$total=$plan.Count+3
        $budget=285
        foreach($task in $plan){$budget+=$task.seconds}
        $extras=@{}
        foreach($task in $plan){
            $step++
            if($Progress){& $Progress $task.label $step $total $budget}
            $watch=[Diagnostics.Stopwatch]::StartNew()
            try {
                $part=[EvgeniumProcess]::Run($gui,('--command support-check-'+$task.id),'',($task.seconds*1000),$pump)
                if($part.ExitCode -ne 0){throw 'probe failed'}
                $extras[$task.id]=$part.Output | ConvertFrom-Json
            } catch {
                $kind=if($_.Exception.GetBaseException() -is [TimeoutException]){'timeout'}else{'error'}
                $extras[$task.id]=@{status=$kind;elapsed_ms=[Math]::Min(120000,[int]$watch.ElapsedMilliseconds)}
            }
            $budget-=$task.seconds
        }
        if($Progress){& $Progress 'Подготовка VPN для сетевого теста' ($step+1) $total 285}
    }
    try {
        if (!(Tunnel-Running)) {$null=Connect-Vpn}
    } catch {
        if(!$Full){throw}
        $network='connect_failed'
    }
    if($Progress){& $Progress 'Маршруты, отправка, UDP, DNS и доступность сервисов' ($step+2) $total 225}
    if($network -eq 'ok'){
        try {
            $result=[EvgeniumProcess]::Run($exe,('diagnose '+$script:Sid),'',180000,$pump)
            if ($result.ExitCode -ne 0) {throw 'Диагностика сети не завершилась.'}
            $checks=$result.Output | ConvertFrom-Json
        } catch {
            if(!$Full){throw}
            $network=if($_.Exception.GetBaseException() -is [TimeoutException]){'timeout'}else{'error'}
        }
    }
    $after=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
    $adapter=@(Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Select-Object -First 64 | ForEach-Object {
        @{received_bytes=[long]$_.ReceivedBytes;sent_bytes=[long]$_.SentBytes;received_errors=[long]$_.ReceivedPacketErrors;sent_errors=[long]$_.OutboundPacketErrors;received_discards=[long]$_.ReceivedDiscardedPackets;sent_discards=[long]$_.OutboundDiscardedPackets}
    })
    $report=@{schema=1;event='support_bundle';system='windows';manager=$script:Version;report_id=([Guid]::NewGuid().ToString('N'));time=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();os_build=[Environment]::OSVersion.Version.Build;checks=$checks;counters=@{tcp_sent=[Math]::Max(0,$after.SegmentsSent-$before.SegmentsSent);tcp_received=[Math]::Max(0,$after.SegmentsReceived-$before.SegmentsReceived);tcp_retransmitted=[Math]::Max(0,$after.SegmentsResent-$before.SegmentsResent)};adapters=$adapter}
    if($Full){$report.schema=2;$report.local=$extras;$report.network_status=$network}
    Protect-Directory $script:Data
    $path=Join-Path $script:Data ('report-'+$report.report_id+'.json')
    Save-PrivateJSON $path $report
    return $report
}
function Send-Report($Report) {
    $state=Read-State
    if (!$state.token -or !$state.private_key) {throw 'Для отправки отчёта подтвердите токен клиента.'}
    $session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $csrf=Invoke-RestMethod -UseBasicParsing -Uri ($script:Api+'/api/session') -WebSession $session -TimeoutSec 15
    $key=Invoke-Engine 'pubkey' (Unseal $state.private_key)
    $body=@{token=(Unseal $state.token);device=$state.device;public_key=$key;report=$Report} | ConvertTo-Json -Depth 15 -Compress
    try {
        $reply=Invoke-RestMethod -UseBasicParsing -Method Post -Uri ($script:Api+'/api/report') -WebSession $session -Headers @{'X-CSRF-Token'=$csrf.csrf} -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 30
        if (!$reply.ok -or $reply.report_id -cne $Report.report_id) {throw 'Сервер не подтвердил сохранение отчёта.'}
        return $Report.report_id
    } finally {$body=$null}
}
