function Snapshot-Desktop($Window) {
    $state=Read-State
    $status=Read-EngineStatus
    $running=Tunnel-Running
    if ($running -and $status.updated -lt ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-30)) {$status.state='recovering';$status.message='Служба отвечает с задержкой. Восстанавливаю связь…'}
    $value=@{has_token=[bool]$state.token;device_name=$state.name;running=$running;engine=$status;policy=(Read-Policy);options=(Read-Options);routes=@(Invoke-Engine 'routes' | ConvertFrom-Json)}
    $Window.SetSnapshot(($value | ConvertTo-Json -Depth 12 -Compress))
}
function Show-Gui([switch]$WidgetOnly) {
    Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing
    $window=New-Object EvgeniumDesktop
    $closeEvent=New-Object Threading.EventWaitHandle($false,[Threading.EventResetMode]::AutoReset,'Local\EvgeniumNetwork.Close')
    $handler={param($action,$raw)
        $request=$raw | ConvertFrom-Json
        if ($action -in @('refresh','running','token-edit')) {
            try {
                switch($action){'refresh'{Snapshot-Desktop $window};'running'{$window.SetApps((ConvertTo-Json -InputObject @(Get-RunningApps) -Compress))};'token-edit'{$saved=Read-State;$window.SetTokenEditing($(if($saved.token){Unseal $saved.token}else{''}))}}
            }catch{$window.StatusText.Text=$_.Exception.Message}
            return
        }
        $window.SetBusy($true);[Windows.Forms.Application]::DoEvents()
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
        } catch {$window.StatusText.Text=$_.Exception.Message}
        finally {if(!$window.IsDisposed){$window.SetBusy($false)}}
    }.GetNewClosure()
    $window.add_Operation($handler)
    $timer=New-Object Windows.Forms.Timer;$timer.Interval=2000
    $timer.add_Tick({
        if($closeEvent.WaitOne(0)){$window.ExitApplication();return}
        if(!$window.Busy){try{Snapshot-Desktop $window}catch{$window.StatusText.Text=$_.Exception.Message}}
    }.GetNewClosure())
    $window.add_Shown({if($WidgetOnly){$window.Hide()}}.GetNewClosure())
    try {
        Snapshot-Desktop $window
        $window.SetApps((ConvertTo-Json -InputObject @(Get-RunningApps) -Compress))
        $timer.Start();[Windows.Forms.Application]::Run($window)
    }finally{$timer.Stop();$timer.Dispose();$closeEvent.Dispose();$window.Dispose()}
}
function Test-Desktop {
    Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing
    $window=New-Object EvgeniumDesktop
    try {
        $sample=@{has_token=$true;device_name='Устройство-1';running=$false;engine=@{state='disconnected';message='VPN отключён.';protected=$false;ranking=@()};policy=@{applications=@();networks=@();ports=@();dns=@();disabled_base=@();route='auto'};options=@{widget=$false;startup=$false};routes=@()}
        $window.SetSnapshot(($sample | ConvertTo-Json -Depth 8 -Compress));$window.Show();$window.Refresh();[Windows.Forms.Application]::DoEvents()
        if($window.Controls.Count -lt 2){throw 'Desktop layout missing'}
        $bitmap=New-Object Drawing.Bitmap($window.Width,$window.Height);$window.DrawToBitmap($bitmap,(New-Object Drawing.Rectangle(0,0,$window.Width,$window.Height)))
        if($env:RUNNER_TEMP){$bitmap.Save((Join-Path $env:RUNNER_TEMP 'evgenium-windows-ui.png'),[Drawing.Imaging.ImageFormat]::Png)};$bitmap.Dispose()
    }finally{$window.AllowExit=$true;$window.Close();$window.Dispose()}
}
