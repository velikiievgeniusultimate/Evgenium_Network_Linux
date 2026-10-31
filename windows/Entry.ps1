try {
    if ($ResultId -and $ResultId -notmatch '^[a-f0-9]{32}$') { throw 'Некорректный идентификатор операции.' }
    if ($ExpectedSid -and $ExpectedSid -ne $script:Sid) { throw 'UAC выполнен под другой учётной записью. Используйте ту же учётную запись Windows.' }
    if (![Environment]::Is64BitProcess) { throw 'Эта сборка предназначена для Windows x64.' }
    switch ($Command.ToLowerInvariant()) {
        'gui' { Show-Gui }
        'widget' { Show-Gui -WidgetOnly }
        'on' { Connect-Vpn }
        'repair' { Connect-Vpn -Repair }
        'off' { Disconnect-Vpn }
        'apply-policy' { if (Invoke-Elevated 'apply-policy') {return}; if (Tunnel-Running) {Write-EngineConfig; $null=Invoke-Engine 'reload'} }
        'uninstall' { Uninstall-App }
        'selftest' { Self-Test }
        'prepare' { Prepare-App }
        'status' { (Read-EngineStatus).state }
        'ui-selftest' { Test-Desktop }
        'close-gui' { try {$e=[Threading.EventWaitHandle]::OpenExisting('Local\EvgeniumNetwork.Close'); $null=$e.Set();$e.Dispose()} catch {} }
        default { throw 'Неподдерживаемая внутренняя операция.' }
    }
} catch {
    $global:EvgeniumExitCode=1; $failure=$_.Exception.Message
    if ($Command -in @('gui','widget','uninstall')) { Add-Type -AssemblyName System.Windows.Forms; $null=[Windows.Forms.MessageBox]::Show($failure,'Evgenium') }
}
if ($ResultId -match '^[a-f0-9]{32}$' -and $ExpectedSid -eq $script:Sid) {
    try {
        Protect-Directory $script:Data
        $path=Join-Path $script:Data ('operation-'+$ResultId+'.json'); Assert-NoReparse $path
        $message=if ($global:EvgeniumExitCode) {$failure} else {''}
        [IO.File]::WriteAllText($path,(@{ok=($global:EvgeniumExitCode -eq 0);message=$message} | ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
    } catch { $global:EvgeniumExitCode=1 }
}
