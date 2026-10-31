function Snapshot-Desktop($Window) {
    $state=Read-State
    $status=Read-EngineStatus
    $running=Tunnel-Running
    if ($running -and $status.updated -lt ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-30)) {$status.state='recovering';$status.message='Служба отвечает с задержкой. Восстанавливаю связь…'}
    $value=@{has_token=[bool]$state.token;device_name=$state.name;running=$running;engine=$status;policy=(Read-Policy);options=(Read-Options);routes=@(Invoke-Engine 'routes' | ConvertFrom-Json)}
    $Window.SetSnapshot(($value | ConvertTo-Json -Depth 12 -Compress))
}
function Show-Gui([switch]$WidgetOnly) {
    Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName PresentationFramework
    $window=New-Object EvgeniumDesktop
    $closeEvent=New-Object Threading.EventWaitHandle($false,[Threading.EventResetMode]::AutoReset,'Local\EvgeniumNetwork.Close')
    $handler={param($action,$raw)
        $request=$raw | ConvertFrom-Json
        if ($action -in @('refresh','running','token-edit')) {
            try {
                switch($action){'refresh'{Snapshot-Desktop $window};'running'{$window.SetApps((ConvertTo-Json -InputObject @(Get-RunningApps) -Compress))};'token-edit'{$saved=Read-State;$window.SetTokenEditing($(if($saved.token){Unseal $saved.token}else{''}))}}
            }catch{$window.SetError($_.Exception.Message)}
            return
        }
        $window.SetBusy($true);[EvgeniumDesktop]::PumpEvents()
        try {
            switch ($action) {
                'toggle' {if ((Tunnel-Running) -or (Read-EngineStatus).protected) {$null=Disconnect-Vpn}else{$null=Connect-Vpn}}
                'repair' {$null=Connect-Vpn -Repair}
                'token-save' {Set-Token $request.token ''; $window.SavedToken()}
                'rename' {Rename-Device $request.name; $window.SavedName()}
                {$_ -in @('add','remove','base','route')} {Change-Policy $action $request}
                'option' {Set-Option $request.name ([bool]$request.value)}
                'update' {$message=Update-App;if($global:EvgeniumInstallerStarted){$window.ExitApplication();return};[Windows.Forms.MessageBox]::Show(($message -join "`n"),'Evgenium')}
                'diagnostic' {
                    $answer=[Windows.Forms.MessageBox]::Show('Проверка включит VPN при необходимости и проверит маршруты, скорость, UDP-пакеты, DNS/HTTPS и сервисы. Затем отчёт автоматически уйдёт на ваш сервер. В нём будут технические счётчики и результаты тестов; токен, ключи, имена приложений, история и содержимое трафика не включаются. Тест может потратить до 15 МБ и занять несколько минут. Продолжить?','Полная диагностика',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Information)
                    if($answer -ne [Windows.Forms.DialogResult]::Yes){return}
                    $report=Create-Report
                    try {$id=Send-Report $report;$window.LastReport='Отчёт отправлен: '+$id}
                    catch {$window.LastReport='Отчёт сохранён на этом устройстве, но отправка не удалась: '+$_.Exception.Message;throw}
                }
            }
            Snapshot-Desktop $window
            if($action -in @('add','remove','base')){$window.RefreshPolicy()}
        } catch {$window.SetError($_.Exception.Message)}
        finally {if(!$window.IsDisposed){$window.SetBusy($false)}}
    }.GetNewClosure()
    $window.add_Operation($handler)
    $timer=New-Object Windows.Threading.DispatcherTimer;$timer.Interval=[TimeSpan]::FromSeconds(2)
    $timer.add_Tick({
        if($closeEvent.WaitOne(0)){$window.ExitApplication();return}
        if(!$window.Busy){try{Snapshot-Desktop $window}catch{$window.SetError($_.Exception.Message)}}
    }.GetNewClosure())
    # The retired floating widget is intentionally not recreated on upgrade.
    $application=New-Object Windows.Application;$application.ShutdownMode='OnMainWindowClose'
    try {
        Snapshot-Desktop $window
        $window.SetApps((ConvertTo-Json -InputObject @(Get-RunningApps) -Compress))
        $timer.Start();$null=$application.Run($window)
    }finally{$timer.Stop();$closeEvent.Dispose();$window.Dispose()}
}
function Test-Desktop {
    Add-Type -AssemblyName PresentationFramework
    $window=New-Object EvgeniumDesktop
    try {
        $sample=@{has_token=$true;device_name='Устройство-1';running=$false;engine=@{state='disconnected';message='VPN отключён.';protected=$false;ranking=@()};policy=@{applications=@('C:\Program Files\Очень длинное название приложения\application.exe');networks=@('subdomain.long-example.com');ports=@('tcp:30000-40000:out');dns=@('192.168.0.1');disabled_base=@();route='auto'};options=@{widget=$true;startup=$false};routes=@(@{id='long-route';label='Очень длинное название маршрута — HSVDS → Эстония — резервный транспорт'})}
        $window.SetSnapshot(($sample | ConvertTo-Json -Depth 8 -Compress));$window.Show();[EvgeniumDesktop]::PumpEvents()
        if($window.WindowStyle -ne 'None' -or $window.ResizeMode -ne 'CanResize'){throw 'Custom chrome or resizing unavailable'}
        if(!$window.FindVisual('windowTitleBar') -or !$window.FindVisual('minimizeWindow') -or !$window.FindVisual('closeWindow')){throw 'Accessible caption controls missing'}
        $out=if($env:RUNNER_TEMP){Join-Path $env:RUNNER_TEMP 'evgenium-windows'}else{$env:TEMP}
        foreach($size in @(@(860,580),@(1040,740),@(1500,900),@(920,660))) {
            $window.Width=$size[0];$window.Height=$size[1]
            foreach($page in 0..4){$window.Navigate($page);$window.ValidateLayout(1);$window.SavePreview((Join-Path $out ('ui-'+$size[0]+'-page-'+$page+'.png')))}
        }
        # Repeated grow/shrink catches stale pixels and invalid layout on the next frame.
        foreach($i in 1..30){$window.Width=860+($i%7)*80;$window.Height=580+($i%5)*50;[EvgeniumDesktop]::PumpEvents();$window.ValidateLayout(1)}
        $window.Width=1040;$window.Height=740;$window.Navigate(0)
        $window.SetTokenEditing('EVN1-'+('a'*43));$window.ValidateLayout(1);$window.SavedToken()
        $sample.has_token=$false;$sample.engine.message=('Длинное сообщение о состоянии сети. '*12);$window.SetSnapshot(($sample | ConvertTo-Json -Depth 8 -Compress));$window.ValidateLayout(1)
        $sample.has_token=$true;$sample.engine.message='VPN отключён.';$window.SetSnapshot(($sample | ConvertTo-Json -Depth 8 -Compress))
        $window.SetBusy($true);$window.SetBusy($false);$window.WindowState='Minimized';[EvgeniumDesktop]::PumpEvents();if($window.WindowState -ne 'Minimized'){throw 'Minimize failed'}
        $window.OpenMain();$window.Close();if($window.Visible -or $window.IsDisposed){throw 'Close must hide to tray'};$window.OpenMain();[EvgeniumDesktop]::PumpEvents()
        $window.SavePreview((Join-Path $env:RUNNER_TEMP 'evgenium-windows-ui.png'))
        # Native compositor screenshot, in addition to an offscreen render.
        Add-Type -AssemblyName System.Drawing
        $bounds=$window.RestoreBounds;$bmp=New-Object Drawing.Bitmap([int]$window.ActualWidth,[int]$window.ActualHeight);$g=[Drawing.Graphics]::FromImage($bmp)
        try{$g.CopyFromScreen([int]$window.Left,[int]$window.Top,0,0,$bmp.Size);$bmp.Save((Join-Path $out 'ui-native-compositor.png'))}finally{$g.Dispose();$bmp.Dispose()}
        [IO.File]::WriteAllText((Join-Path $out 'ui-selftest.log'),'PASS: 5 pages, 4 sizes, 30 resize cycles, long errors/paths, token edit, native compositor, minimize/tray. Real multi-monitor DPI still needs physical Windows verification.')
    }catch{
        if($env:RUNNER_TEMP){[IO.File]::WriteAllText((Join-Path $env:RUNNER_TEMP 'evgenium-windows/ui-selftest.log'),($_.Exception.ToString()+"`n"+$_.ScriptStackTrace),[Text.Encoding]::UTF8)}
        throw
    }finally{$window.AllowExit=$true;$window.Close();$window.Dispose()}
}
