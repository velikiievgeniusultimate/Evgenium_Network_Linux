param([string]$Command = 'gui', [string]$ExpectedSid = '', [string]$ResultId = '', [string]$ExecutableDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$global:EvgeniumExitCode = 0
$script:Version = '0.2.0'
$global:EvgeniumInstallerStarted = $false
$script:Api = 'https://connect.velikiievgenius.com'
$script:Manifest = 'https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/releases/windows/stable.json'
$script:AppRoot = Join-Path $env:LOCALAPPDATA 'EvgeniumNetwork'
$script:Data = Join-Path $script:AppRoot 'private'
$script:Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:StatePath = Join-Path $script:Data 'state.json'
$script:EngineService = 'EvgeniumNetworkEngine'
$script:EngineData = Join-Path (Join-Path $env:ProgramData 'EvgeniumNetwork') $script:Sid
$script:PolicyPath = Join-Path $script:Data 'policy.json'
$script:OptionsPath = Join-Path $script:Data 'options.json'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security

function Protect-Directory([string]$Path) {
    Assert-NoReparse $Path
    if (!(Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Path $Path -Force }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($script:Sid, 'S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-NoReparse([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if ((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Папка приложения содержит ссылку. Выберите обычную папку.' }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }; $current = $parent
    }
}
function Protect-EngineDirectory {
    if (!(Is-Admin)) {throw 'Для подготовки службы нужны права администратора.'}
    $root=Join-Path $env:ProgramData 'EvgeniumNetwork'
    foreach($path in @($root,$script:EngineData)) {
        Assert-NoReparse $path
        if(!(Test-Path -LiteralPath $path)){$null=New-Item -ItemType Directory -Path $path -Force}
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $admin=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $acl.SetOwner($admin)
        foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
            $identity=New-Object Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
        }
        $reader=if($path -eq $root){'S-1-5-32-545'}else{$script:Sid}
        $identity=New-Object Security.Principal.SecurityIdentifier($reader)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
        Set-Acl -LiteralPath $path -AclObject $acl
    }
}
function Read-State {
    Assert-NoReparse $script:StatePath
    if (Test-Path -LiteralPath $script:StatePath) {
        try { return (Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json) }
        catch { throw 'Локальные настройки повреждены. Не публикуйте этот файл: он содержит защищённые учётные данные.' }
    }
    return [pscustomobject]@{schema=1;device=([Guid]::NewGuid().ToString('N'));name='';token='';private_key='';profile=$null}
}
function Save-State($State) {
    Assert-NoReparse $script:Data; Protect-Directory $script:Data
    $temporary = Join-Path $script:Data ([Guid]::NewGuid().ToString('N') + '.tmp')
    try { [IO.File]::WriteAllText($temporary, ($State | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath $temporary -Destination $script:StatePath -Force }
    finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}
function Seal([string]$Value) {
    return [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Value), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
}
function Unseal([string]$Value) {
    return [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Value), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
}
function Is-Admin { return (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Invoke-Elevated([string]$Action) {
    if ($ExpectedSid -and $ExpectedSid -ne $script:Sid) { throw 'Подтвердите UAC своей учётной записью: токен защищён для текущего пользователя.' }
    if (Is-Admin) { return $false }
    $exe = Join-Path $ExecutableDirectory 'Evgenium.exe'
    if (!(Test-Path -LiteralPath $exe)) { throw 'Файлы приложения повреждены. Повторно запустите установщик.' }
    Protect-Directory $script:Data
    $id=[Guid]::NewGuid().ToString('N'); $reply=Join-Path $script:Data ('operation-'+$id+'.json')
    try {
        try {
            $process = Start-Process -FilePath $exe -ArgumentList @('--command', $Action, '--expected-sid', $script:Sid, '--result-id', $id) -Verb RunAs -PassThru
            while (!$process.HasExited) { if ($Command -eq 'gui') { [Windows.Forms.Application]::DoEvents() }; Start-Sleep -Milliseconds 100; $process.Refresh() }
        } catch { throw 'Для управления VPN нужно подтвердить запрос Windows. Действие отменено.' }
        if (Test-Path -LiteralPath $reply) {
            Assert-NoReparse $reply
            $result=Get-Content -LiteralPath $reply -Raw -Encoding UTF8 | ConvertFrom-Json
            if (!$result.ok) { throw $result.message }
        } elseif ($process.ExitCode -ne 0) { throw 'Операция не выполнена. Подтвердите UAC своей учётной записью Windows и повторите попытку.' }
        if ($process.ExitCode -ne 0) { throw 'Операция не завершена. Повторите попытку.' }
    } finally { if (Test-Path -LiteralPath $reply) { Remove-Item -LiteralPath $reply -Force } }
    return $true
}
function Check-Key([string]$Key) {
    if ($Key -notmatch '^[A-Za-z0-9+/]{43}=$') { return $false }
    $bytes=[Convert]::FromBase64String($Key)
    return ($bytes.Length -eq 32 -and [Convert]::ToBase64String($bytes) -ceq $Key -and @($bytes | Where-Object { $_ -ne 0 }).Count -gt 0)
}
function Validate-Profile($Profile) {
    if (!$Profile -or $Profile.schema -ne 1 -or !(Check-Key $Profile.public_key) -or $Profile.endpoint -ne '195.209.211.163:51820' -or $Profile.address -notmatch '^10\.78\.0\.([2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])/32$' -or $Profile.mtu -ne 1280) { throw 'Сервер вернул неподдерживаемый профиль. VPN не включён.' }
    if ((@($Profile.dns) -join ',') -ne '1.1.1.1,1.0.0.1' -or (@($Profile.allowed_ips).Count -ne 2 -or @($Profile.allowed_ips) -cnotcontains '0.0.0.0/0' -or @($Profile.allowed_ips) -cnotcontains '::/0')) { throw 'Профиль не содержит ожидаемую защиту трафика и DNS.' }
}
function Enroll($State) {
    if (!$State.token) { throw 'Сначала введите токен клиента.' }
    if (!$State.private_key) { $State.private_key = Seal ((Invoke-Engine 'keygen' | ConvertFrom-Json).private_key) }
    $private = Unseal $State.private_key
    $public = Invoke-Engine 'pubkey' $private
    if (!(Check-Key $public)) { throw 'Не удалось создать ключ устройства.' }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    try {
        $csrf = Invoke-RestMethod -UseBasicParsing -Uri ($script:Api + '/api/session') -WebSession $session -TimeoutSec 15
        if ($csrf.csrf -notmatch '^[A-Za-z0-9_-]{20,128}$') { throw 'Неверный ответ сервера.' }
        $body = @{token=(Unseal $State.token);device=$State.device;name=$State.name;public_key=$public} | ConvertTo-Json -Compress
        $reply = Invoke-RestMethod -UseBasicParsing -Method Post -Uri ($script:Api + '/api/enroll') -WebSession $session -Headers @{'X-CSRF-Token'=$csrf.csrf} -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 25
        if (!$reply.ok) { throw 'Отказ регистрации.' }
        Validate-Profile $reply.profile
        $State.profile=$reply.profile; $State.name=$reply.profile.device_name; Save-State $State
    } catch {
        $status = 0
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -eq 401) { throw 'Токен недействителен или доступ отозван. Проверьте токен.' }
        if ($status -eq 429) { throw 'Слишком много попыток. Подождите несколько минут.' }
        throw 'Сервер регистрации недоступен или отклонил запрос. Проверьте обычный интернет и токен; повторите подключение.'
    } finally { $body=$null; $private=$null }
    return $State
}

function Invoke-Engine([string]$Arguments, [string]$InputText = '') {
    $exe=Join-Path $ExecutableDirectory 'EvgeniumEngine.exe'
    if (!(Test-Path -LiteralPath $exe)) { throw 'Сетевое ядро не найдено. Повторно запустите установщик.' }
    $result=[EvgeniumProcess]::Run($exe,$Arguments,$InputText,30000)
    if ($result.ExitCode -ne 0) { throw ('Сетевое ядро: '+$result.Error) }
    return $result.Output
}
function Read-EngineStatus {
    $path=Join-Path $script:EngineData 'status.json'
    if (Test-Path -LiteralPath $path) {
        Assert-NoReparse $path
        try { return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch {}
    }
    return [pscustomobject]@{state='disconnected';message='VPN отключён.';ranking=@();route='';protected=$false;updated=0;restarts=0}
}
function Tunnel-Running {
    $s=Get-Service -Name $script:EngineService -ErrorAction SilentlyContinue
    return ($s -and $s.Status -eq 'Running')
}
function Get-LAN {
    $default=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Where-Object {$_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'EvgeniumTunnel'} | Sort-Object RouteMetric | Select-Object -First 1
    if (!$default) { return @() }
    return @(Get-NetIPAddress -InterfaceIndex $default.InterfaceIndex -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^(127\.|169\.254\.)'} | ForEach-Object {$_.IPAddress+'/'+$_.PrefixLength})
}
function Write-EngineConfig([switch]$Repair) {
    $state=Read-State
    Validate-Profile $state.profile
    Protect-EngineDirectory
    $config=@{schema=1;owner=$script:Sid;private_key=(Unseal $state.private_key);profile=$state.profile;policy=(Read-Policy);lan=@(Get-LAN);reset_rating=[bool]$Repair}
    # Only the engine's whitelist is serialized; enrollment metadata cannot add
    # arbitrary Xray options, executables, endpoints or routing rules.
    $config.profile=@{schema=1;public_key=$state.profile.public_key;endpoint=$state.profile.endpoint;address=$state.profile.address;mtu=$state.profile.mtu}
    $text=$config | ConvertTo-Json -Depth 10
    $null=Invoke-Engine 'validate' $text
    $path=Join-Path $script:EngineData 'engine.json'; $tmp=Join-Path $script:EngineData ([Guid]::NewGuid().ToString('N')+'.tmp')
    try { [IO.File]::WriteAllText($tmp,$text,(New-Object Text.UTF8Encoding($false))); $acl=Get-Acl -LiteralPath $tmp;$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')));Set-Acl -LiteralPath $tmp -AclObject $acl;Move-Item -LiteralPath $tmp -Destination $path -Force }
    finally { $config.private_key=$null; $text=$null; if (Test-Path -LiteralPath $tmp) {Remove-Item -LiteralPath $tmp -Force} }
}
function Connect-Vpn([switch]$Repair) {
    $operation=if ($Repair) {'repair'} else {'on'}
    if (Invoke-Elevated $operation) { return }
    Protect-Directory $script:Data
    $state=Read-State
    if (!$state.token) { throw 'Сначала введите токен клиента.' }
    # Enroll again only when needed. An offline server cannot prevent repair of
    # an already issued device, and an invalid new token never enables a tunnel.
    if (!$state.profile -or !$state.private_key) { $null=Enroll $state }
    Write-EngineConfig -Repair:$Repair
    $null=Invoke-Engine ('install '+$script:Sid)
    for ($i=0;$i -lt 80;$i++) {
        $status=Read-EngineStatus
        if ($status.state -eq 'connected' -and $status.updated -ge [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-15) { return $status.message }
        if ($status.state -eq 'error') { throw $status.message }
        if ($Command -eq 'gui' -or $Command -eq 'widget') { [Windows.Forms.Application]::DoEvents() }
        Start-Sleep -Milliseconds 250
    }
    return 'VPN продолжает подключение и автоматическое восстановление. Защищённый трафик блокируется до связи с Эстонией.'
}
function Disconnect-Vpn {
    if (Invoke-Elevated 'off') { return }
    $null=Invoke-Engine 'remove'
    if (Test-Path -LiteralPath $script:EngineData) {
        $old=Read-EngineStatus
        foreach($name in @('engine.json','core.json','control.key')){$path=Join-Path $script:EngineData $name;if(Test-Path -LiteralPath $path){Assert-NoReparse $path;Remove-Item -LiteralPath $path -Force}}
        $old.state='disconnected';$old.protected=$false;$old.message='VPN отключён.'
        [IO.File]::WriteAllText((Join-Path $script:EngineData 'status.json'),($old | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    }
    return 'VPN отключён. Обычное подключение восстановлено.'
}
function Set-Token([string]$Token, [string]$Name) {
    $Token=$Token.Trim()
    if ($Token -notmatch '^EVN1-[A-Za-z0-9_-]{43}$') { throw 'Ожидается полный токен EVN1-…' }
    if (Tunnel-Running) { throw 'Отключите VPN перед изменением токена.' }
    if (!$Name.Trim()) {$Name=''}
    if ($Name.Length -gt 64 -or $Name -match '\p{C}') { throw 'Имя устройства должно содержать не больше 64 символов.' }
    $state=Read-State
    if ($state.token -and (Unseal $state.token) -ne $Token) { $state=[pscustomobject]@{schema=1;device=([Guid]::NewGuid().ToString('N'));name=$Name;token='';private_key='';profile=$null} }
    $state.token=Seal $Token; $state.name=$Name
    # The user's old saved token is preserved if verification fails.
    $null=Enroll $state
}
function Rename-Device([string]$Name) {
    $Name=$Name.Normalize([Text.NormalizationForm]::FormC).Trim()
    if (!$Name -or $Name.Length -gt 64 -or $Name -match '\p{C}') {throw 'Имя устройства должно содержать от 1 до 64 символов.'}
    $state=Read-State; $state.name=$Name; $null=Enroll $state
}
function Assert-SafeTree([string]$Path) {
    Assert-NoReparse $Path
    if (Test-Path -LiteralPath $Path -PathType Container) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Папка приложения содержит ссылку. Удаление остановлено, чтобы сохранить посторонние данные.' }
            if ($child.PSIsContainer) { Assert-SafeTree $child.FullName }
        }
    }
}
function Uninstall-App {
    if (Invoke-Elevated 'uninstall') {return}
    $null=Invoke-Engine 'uninstall-all'
    $profiles=Get-CimInstance Win32_UserProfile | Where-Object {!$_.Special -and $_.SID -match '^S-1-5-21-' -and $_.LocalPath}
    foreach($profile in $profiles){
        $root=Join-Path $profile.LocalPath 'AppData\Local\EvgeniumNetwork'
        $startup=Join-Path $profile.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Evgenium Network.lnk'
        foreach($path in @($root,$startup)){if(Test-Path -LiteralPath $path){Assert-SafeTree $path;Remove-Item -LiteralPath $path -Recurse -Force}}
    }
    $root=Join-Path $env:ProgramData 'EvgeniumNetwork'
    if(Test-Path -LiteralPath $root){Assert-SafeTree $root;Remove-Item -LiteralPath $root -Recurse -Force}
}
function Self-Test {
    Validate-Profile ([pscustomobject]@{schema=1;public_key='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';endpoint='195.209.211.163:51820';address='10.78.0.2/32';dns=@('1.1.1.1','1.0.0.1');mtu=1280;allowed_ips=@('0.0.0.0/0','::/0')})
    $null=Invoke-Engine 'selftest'
}
function Validate-Manifest($Manifest) {
    if ($Manifest.schema -ne 2 -or $Manifest.version -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$') { throw 'Некорректный манифест обновления.' }
    $base='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/windows-v' + $Manifest.version + '/Evgenium-Windows-' + $Manifest.version + '-x64'
    if ($Manifest.installer_url -cne ($base+'-Setup.exe') -or $Manifest.installer_sha256 -notmatch '^[a-f0-9]{64}$' -or $Manifest.installer_size -lt 100000 -or $Manifest.installer_size -gt 100MB) { throw 'Манифест не содержит проверенный установщик Evgenium.' }
}
function Assert-Installer([string]$Path,$Manifest) {
    Validate-Manifest $Manifest
    if((Get-Item -LiteralPath $Path).Length -ne $Manifest.installer_size -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Manifest.installer_sha256){throw 'Контрольная сумма обновления не совпала. Текущая версия сохранена.'}
}
function Start-VerifiedInstaller($Manifest) {
    Validate-Manifest $Manifest
    Assert-NoReparse $script:AppRoot; Protect-Directory $script:AppRoot
    $downloads=Join-Path $script:AppRoot 'updates'; Protect-Directory $downloads
    # A new private directory prevents substitution of a predictable download path.
    $stage=Join-Path $downloads ([Guid]::NewGuid().ToString('N')); Protect-Directory $stage
    $installer=Join-Path $stage 'Setup.exe'; $started=$false
    try {
        $null=Invoke-WebRequest -UseBasicParsing -Uri $Manifest.installer_url -OutFile $installer -TimeoutSec 180
        Assert-Installer $installer $Manifest
        $null=Start-Process -FilePath $installer -ArgumentList '/SILENT','/SUPPRESSMSGBOXES','/NORESTART','/CLOSEAPPLICATIONS' -PassThru
        $started=$true; $global:EvgeniumInstallerStarted=$true
    } finally { if (!$started -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force } }
}
function Update-App([switch]$InstallCurrent) {
    $manifest=Invoke-RestMethod -UseBasicParsing -Uri $script:Manifest -TimeoutSec 20
    Validate-Manifest $manifest
    if ([version]$manifest.version -lt [version]$script:Version) { throw 'В репозитории пока нет установщика этой версии. Повторите позже.' }
    if (!$InstallCurrent -and [version]$manifest.version -eq [version]$script:Version) { Write-Output ('Установлена актуальная версия ' + $script:Version + '.'); return }
    Start-VerifiedInstaller $manifest
    Write-Output 'Обновление проверено. Приложение закроется и откроется после установки. На время перезапуска VPN защищённые подключения приостановятся.'
}
