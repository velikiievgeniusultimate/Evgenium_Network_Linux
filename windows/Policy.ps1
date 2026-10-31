function Read-Policy {
    $value=[pscustomobject]@{applications=@();networks=@();ports=@();dns=@();disabled_base=@();route='auto'}
    if (Test-Path -LiteralPath $script:PolicyPath) {
        Assert-NoReparse $script:PolicyPath
        $saved=Get-Content -LiteralPath $script:PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($name in @('applications','networks','ports','dns','disabled_base','route')) {
            if ($saved.PSObject.Properties[$name]) {$value.$name=$saved.$name}
        }
    }
    return $value
}
function Save-PrivateJSON([string]$Path,$Value) {
    Protect-Directory $script:Data; Assert-NoReparse $Path
    $temp=Join-Path $script:Data ([Guid]::NewGuid().ToString('N')+'.tmp')
    try {[IO.File]::WriteAllText($temp,($Value | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)));Move-Item -LiteralPath $temp -Destination $Path -Force}
    finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
}
function Normalize-Exception([string]$Category,[string]$Value) {
    $Value=$Value.Trim()
    if ($Category -notin @('applications','networks','ports','dns')) {throw 'Неизвестная категория исключений.'}
    if ($Category -eq 'networks') {
        $Value=$Value.ToLowerInvariant().TrimEnd('.')
        if ($Value -notmatch '^[\d./]+$') {
            $exact=$Value.StartsWith('=');$Value=$Value.TrimStart('=')
            try {$Value=(New-Object Globalization.IdnMapping).GetAscii($Value)} catch {throw 'Некорректный домен.'}
            if ($exact) {$Value='='+$Value}
        }
    }
    $body=@{category=$Category;value=$Value} | ConvertTo-Json -Compress
    $null=Invoke-Engine 'validate-exception' $body
    return $Value
}
function Change-Policy([string]$Action,$Request) {
    $p=Read-Policy
    switch ($Action) {
        'add' {$v=Normalize-Exception $Request.category $Request.value;$p.($Request.category)=@(@($p.($Request.category))+$v | Select-Object -Unique)}
        'remove' {if ($Request.category -notin @('applications','networks','ports','dns')) {throw 'Неизвестная категория.'};$p.($Request.category)=@($p.($Request.category) | Where-Object {$_ -cne $Request.value})}
        'base' {
            if ($Request.value -notin @('networks:lan','networks:linklocal','ports:discovery','dns:stub')) {throw 'Неизвестное базовое правило.'}
            if ($Request.enabled) {$p.disabled_base=@($p.disabled_base | Where-Object {$_ -ne $Request.value})}
            else {$p.disabled_base=@(@($p.disabled_base)+$Request.value | Select-Object -Unique)}
        }
        'route' {
            $routes=@('auto')+@((Invoke-Engine 'routes' | ConvertFrom-Json) | ForEach-Object {$_.id})
            if ($Request.value -notin $routes) {throw 'Неизвестный маршрут.'};$p.route=$Request.value
        }
    }
    # Keep a valid saved policy if live application is cancelled or fails. The
    # UI explicitly reports that reconnect is needed instead of claiming success.
    Save-PrivateJSON $script:PolicyPath $p
    if (Tunnel-Running) {
        try {if (!(Invoke-Elevated 'apply-policy')) {Write-EngineConfig;$null=Invoke-Engine 'reload'}}
        catch {throw ('Правило сохранено. Применение не завершено: '+$_.Exception.Message+' Нажмите «Восстановить», чтобы применить его.')}
    }
}
function Read-Options {
    $o=[pscustomobject]@{widget=$false;startup=$false}
    if (Test-Path -LiteralPath $script:OptionsPath) {
        Assert-NoReparse $script:OptionsPath
        try {$v=Get-Content -LiteralPath $script:OptionsPath -Raw -Encoding UTF8 | ConvertFrom-Json;foreach($k in @('widget','startup')){if($v.PSObject.Properties[$k]){$o.$k=[bool]$v.$k}}} catch {}
    }
    return $o
}
function Set-Option([string]$Name,[bool]$Value) {
    if ($Name -notin @('widget','startup')) {throw 'Неизвестная настройка.'}
    $o=Read-Options; $o.$Name=$Value
    if ($Name -eq 'startup') {
        $path=Join-Path ([Environment]::GetFolderPath('Startup')) 'Evgenium Network.lnk'
        if($Value){$shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut($path);$link.TargetPath=Join-Path $ExecutableDirectory 'Evgenium.exe';$link.Arguments='--command widget';$link.WorkingDirectory=$ExecutableDirectory;$link.Save()}
        elseif(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}
    }
    Save-PrivateJSON $script:OptionsPath $o
}
function Get-RunningApps {
    return @(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId} | ForEach-Object {
        try {if ($_.Path) {@{name=($_.ProcessName+'.exe');exe=$_.Path}}} catch {}
    } | Sort-Object -Property @{Expression={$_.exe}} -Unique)
}
