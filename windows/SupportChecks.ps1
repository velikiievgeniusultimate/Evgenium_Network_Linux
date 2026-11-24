function Get-EvgSupportPlan {
    return @(
        @{id='temp'; label='Запись в локальную временную папку'; seconds=6}
        @{id='desktop'; label='Запись на Рабочий стол'; seconds=8}
        @{id='documents'; label='Запись в Документы'; seconds=8}
        @{id='downloads'; label='Запись в Загрузки'; seconds=8}
        @{id='telegram_files'; label='Папка загрузок Telegram'; seconds=7}
        @{id='shell_desktop'; label='Открытие Рабочего стола в Проводнике'; seconds=7}
        @{id='shell_downloads'; label='Открытие Загрузок в Проводнике'; seconds=7}
        @{id='applications'; label='Photoshop, Telegram и OneDrive'; seconds=6}
        @{id='storage'; label='Место на дисках и права пользователя'; seconds=6}
        @{id='settings'; label='Сетевые диски, SMB, прокси и защита папок'; seconds=9}
        @{id='events'; label='Недавние зависания и блокировки приложений'; seconds=8}
    )
}

function Get-EvgKnownPath([string]$Id) {
    switch ($Id) {
        'temp' { [IO.Path]::GetTempPath() }
        { $_ -in @('desktop','shell_desktop') } { [Environment]::GetFolderPath('DesktopDirectory','DoNotVerify') }
        'documents' { [Environment]::GetFolderPath('MyDocuments','DoNotVerify') }
        default {
            $key=Get-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue
            $path=if($key){$key.GetValue('{374DE290-123F-4565-9164-39C4925E467B}')}
            if(!$path){$path=Join-Path $env:USERPROFILE 'Downloads'}
            if($Id -eq 'telegram_files'){Join-Path $path 'Telegram Desktop'}else{$path}
        }
    }
}

function Get-EvgSupportPathKind([string]$Path) {
    if (!$Path) { return 'unknown' }
    if ($Path.StartsWith('\\',[StringComparison]::Ordinal)) { return 'network' }
    $root=[IO.Path]::GetPathRoot($Path)
    if (!$root -or $root -notmatch '^[A-Za-z]:\\$') { return 'unknown' }
    $disk=New-Object IO.DriveInfo $root
    if ($disk.DriveType -eq [IO.DriveType]::Network) { return 'network' }
    if ($disk.DriveType -ne [IO.DriveType]::Fixed) { return 'unknown' }
    $cloud=@($env:OneDrive,$env:OneDriveConsumer,$env:OneDriveCommercial)
    foreach($account in @(Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue)) {
        $cloud+= [string]$account.GetValue('UserFolder','')
    }
    foreach($location in $cloud) {
        if(!$location){continue}
        $prefix=$location.TrimEnd('\')
        if($Path.Equals($prefix,[StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($prefix+'\',[StringComparison]::OrdinalIgnoreCase)){return 'cloud'}
    }
    # Follow the original path only for metadata. No test writes through a junction or cloud placeholder.
    $parent=[IO.DirectoryInfo]::new($Path)
    while($parent -and $parent.Parent){
        if($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){return 'reparse'}
        $parent=$parent.Parent
    }
    return 'local'
}

function Get-EvgSupportError($Failure) {
    $root=$Failure.GetBaseException()
    if($root -is [UnauthorizedAccessException]){return 'denied'}
    switch ($root.HResult -band 65535) {
        {$_ -in @(2,3)} {return 'missing'}
        5 {return 'denied'}
        {$_ -in @(32,33)} {return 'busy'}
        {$_ -in @(53,64,67,121,1231)} {return 'network'}
        112 {return 'disk_full'}
        206 {return 'long_path'}
        default {return 'error'}
    }
}

function Test-EvgSupportFile([string]$Path) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $row=@{kind='unknown';status='error';step='lookup';elapsed_ms=0;read_only=$false;cleanup_ok=$true}
    $dir=$null;$first=$null;$second=$null;$owned=$false
    try {
        $row.kind=Get-EvgSupportPathKind $Path
        if($row.kind -ne 'local'){
            $row.status=if($row.kind -eq 'unknown'){'unavailable'}else{'read_only'}
            if($row.kind -eq 'cloud' -or $row.kind -eq 'reparse'){
                if([IO.Directory]::Exists($Path)){$row.read_only=[bool]([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReadOnly)}
            }
        } elseif(![IO.Directory]::Exists($Path)){
            $row.status='missing'
        } else {
            $row.read_only=[bool]([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReadOnly)
            $dir=Join-Path $Path ('Evgenium-Probe-'+[Guid]::NewGuid().ToString('N'))
            $first=Join-Path $dir 'write.tmp';$second=Join-Path $dir 'save.tmp'
            $row.step='mkdir'
            if([IO.Directory]::Exists($dir)){throw [IO.IOException]::new('Test directory collision')}
            $null=[IO.Directory]::CreateDirectory($dir);$owned=$true
            $row.step='write'
            $data=[Text.Encoding]::ASCII.GetBytes('Evgenium Windows support test')
            $stream=[IO.File]::Open($first,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()}
            $row.step='rename';[IO.File]::Move($first,$second)
            $row.step='read'
            if([Convert]::ToBase64String([IO.File]::ReadAllBytes($second)) -cne [Convert]::ToBase64String($data)){throw [IO.IOException]::new('Test integrity mismatch')}
            $row.step='delete';[IO.File]::Delete($second);[IO.Directory]::Delete($dir);$owned=$false
            $row.step='done';$row.status='ok'
        }
    } catch { $row.status=Get-EvgSupportError $_.Exception }
    finally {
        if($owned){
            try{[IO.File]::Delete($first);[IO.File]::Delete($second);[IO.Directory]::Delete($dir)}
            catch{$row.cleanup_ok=$false}
        }
        $row.elapsed_ms=[Math]::Min(120000,[int]$clock.ElapsedMilliseconds)
    }
    return $row
}

function Test-EvgSupportShell([string]$Path) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $row=@{kind='unknown';status='unavailable';step='shell';elapsed_ms=0;read_only=$false;cleanup_ok=$true}
    try {
        $row.kind=Get-EvgSupportPathKind $Path
        if($Path){
            $shell=New-Object -ComObject Shell.Application
            $folder=$shell.NameSpace($Path)
            if($folder){
                $null=$folder.Items().Item(0)
                $row.status=if(([string]$folder.Self.Path).TrimEnd('\') -ieq $Path.TrimEnd('\')){'ok'}else{'redirected'}
            }
        }
    } catch { $row.status=Get-EvgSupportError $_.Exception }
    $row.elapsed_ms=[Math]::Min(120000,[int]$clock.ElapsedMilliseconds)
    return $row
}

function Get-EvgSupportAppState {
    $photoshop=Test-Path -Path (Join-Path $env:ProgramFiles 'Adobe\Adobe Photoshop*\Photoshop.exe') -ErrorAction SilentlyContinue
    $telegram=Test-Path -LiteralPath (Join-Path $env:APPDATA 'Telegram Desktop\Telegram.exe')
    if(!$telegram -and (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)){
        $telegram=[bool](Get-AppxPackage -Name '*TelegramDesktop*' -ErrorAction SilentlyContinue | Select-Object -First 1)
    }
    return @{
        photoshop_installed=[bool]$photoshop
        photoshop_running=[bool](Get-Process Photoshop -ErrorAction SilentlyContinue)
        photoshop_profile=[bool](Test-Path (Join-Path $env:APPDATA 'Adobe'))
        telegram_installed=[bool]$telegram
        telegram_running=[bool](Get-Process Telegram -ErrorAction SilentlyContinue)
        onedrive_configured=[bool]($env:OneDrive -or $env:OneDriveConsumer -or $env:OneDriveCommercial -or
                                  (Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue))
        onedrive_running=[bool](Get-Process OneDrive -ErrorAction SilentlyContinue)
    }
}

function Get-EvgSupportStorage {
    $principal=New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    $fixed=@([IO.DriveInfo]::GetDrives() | Where-Object {$_.DriveType -eq 'Fixed' -and $_.IsReady})
    $low=@($fixed | Where-Object {$_.AvailableFreeSpace -lt 2GB})
    $root=[IO.Path]::GetPathRoot([IO.Path]::GetTempPath());$temp=New-Object IO.DriveInfo $root
    return @{fixed_disks=$fixed.Count;low_space_disks=$low.Count;temp_free_mb=[Math]::Min(4000000,[Math]::Floor($temp.AvailableFreeSpace/1MB));
             elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
}

function Get-EvgSupportSettings {
    $drives=@(Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue)
    $reachable=0;$checked=0
    foreach($drive in @($drives | Select-Object -First 4)){
        $value=[string]$drive.GetValue('RemotePath','')
        if($value -notmatch '^\\\\([^\\]+)\\'){continue}
        $hostname=$Matches[1];$checked++
        $client=New-Object Net.Sockets.TcpClient
        try{
            $pending=$client.ConnectAsync($hostname,445)
            if($pending.Wait(850) -and $client.Connected){$reachable++}
        }catch{}finally{$client.Dispose()}
    }
    $inet=Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $guard=Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' -ErrorAction SilentlyContinue
    $cfa=if($guard){[int]$guard.GetValue('EnableControlledFolderAccess',-1)}else{-1}
    $smb=Get-Service LanmanWorkstation -ErrorAction SilentlyContinue
    $lan=if(Get-Command Get-LAN -ErrorAction SilentlyContinue){@(Get-LAN).Count}else{0}
    return @{mapped_disks=$drives.Count;smb_checked=$checked;smb_reachable=$reachable;lan_subnets=$lan
             smb_running=[bool]($smb -and $smb.Status -eq 'Running');proxy=[bool]($inet -and $inet.GetValue('ProxyEnable',0))
             proxy_pac=[bool]($inet -and $inet.GetValue('AutoConfigURL',''));defender_cfa=[Math]::Max(-1,[Math]::Min(4,$cfa))}
}

function Get-EvgSupportEvents {
    $start=(Get-Date).AddDays(-7)
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';ID=1000,1001,1002;StartTime=$start} -MaxEvents 150 -ErrorAction SilentlyContinue)
    $counts=@{photoshop_events=0;telegram_events=0;explorer_events=0;onedrive_events=0;cfa_blocked=0;cfa_audited=0}
    foreach($event in $events){
        $data=($event.Properties | ForEach-Object {$_.Value}) -join ' '
        foreach($app in @('photoshop','telegram','explorer','onedrive')){
            if($data -match ('(?i)\b'+$app+'\.exe\b')){$counts[$app+'_events']++}
        }
    }
    foreach($event in @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1123,1124;StartTime=$start} -MaxEvents 100 -ErrorAction SilentlyContinue)){
        $data=($event.Properties | ForEach-Object {$_.Value}) -join ' '
        if($data -match '(?i)\b(photoshop|telegram|explorer|onedrive)\.exe\b'){
            if($event.Id -eq 1123){$counts.cfa_blocked++}else{$counts.cfa_audited++}
        }
    }
    $counts.application_log_available=[bool](Get-WinEvent -ListLog 'Application' -ErrorAction SilentlyContinue)
    $counts.defender_log_available=[bool](Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction SilentlyContinue)
    return $counts
}

function Invoke-EvgSupportCheck([string]$Id) {
    switch ($Id) {
        {$_ -in @('temp','desktop','documents','downloads','telegram_files')} { Test-EvgSupportFile (Get-EvgKnownPath $Id);break }
        {$_ -in @('shell_desktop','shell_downloads')} { Test-EvgSupportShell (Get-EvgKnownPath $Id);break }
        'applications' { Get-EvgSupportAppState }
        'storage' { Get-EvgSupportStorage }
        'settings' { Get-EvgSupportSettings }
        'events' { Get-EvgSupportEvents }
        default { throw 'Неизвестная проверка поддержки.' }
    }
}
