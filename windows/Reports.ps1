function Create-Report {
    if (!(Tunnel-Running)) {$null=Connect-Vpn}
    $exe=Join-Path $ExecutableDirectory 'EvgeniumEngine.exe'
    $before=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
    $result=[EvgeniumProcess]::Run($exe,('diagnose '+$script:Sid),'',180000)
    if ($result.ExitCode -ne 0) {throw 'Диагностика не завершилась. Проверьте, что VPN подключён, и повторите.'}
    $after=[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetTcpIPv4Statistics()
    $checks=$result.Output | ConvertFrom-Json
    $adapter=@(Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object {
        @{received_bytes=[long]$_.ReceivedBytes;sent_bytes=[long]$_.SentBytes;received_errors=[long]$_.ReceivedPacketErrors;sent_errors=[long]$_.OutboundPacketErrors;received_discards=[long]$_.ReceivedDiscardedPackets;sent_discards=[long]$_.OutboundDiscardedPackets}
    })
    $report=@{schema=1;event='support_bundle';system='windows';manager=$script:Version;report_id=([Guid]::NewGuid().ToString('N'));time=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();os_build=[Environment]::OSVersion.Version.Build;checks=$checks;counters=@{tcp_sent=[Math]::Max(0,$after.SegmentsSent-$before.SegmentsSent);tcp_received=[Math]::Max(0,$after.SegmentsReceived-$before.SegmentsReceived);tcp_retransmitted=[Math]::Max(0,$after.SegmentsResent-$before.SegmentsResent)};adapters=$adapter}
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
