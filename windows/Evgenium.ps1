param([string]$Command = 'gui', [string]$ExpectedSid = '', [string]$ExecutableDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$global:EvgeniumExitCode = 0
$script:Version = '0.1.0'
$script:Api = 'https://connect.velikiievgenius.com'
$script:Manifest = 'https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/releases/windows/stable.json'
$script:AppRoot = Join-Path $env:LOCALAPPDATA 'EvgeniumNetwork'
$script:Data = Join-Path $script:AppRoot 'private'
$script:Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:StatePath = Join-Path $script:Data 'state.json'
$script:Tunnel = 'Evgenium'
$script:Service = 'WireGuardTunnel$Evgenium'
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
function Read-State {
    Assert-NoReparse $script:StatePath
    if (Test-Path -LiteralPath $script:StatePath) {
        try { return (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json) }
        catch { throw 'Локальные настройки повреждены. Не публикуйте этот файл: он содержит защищённые учётные данные.' }
    }
    return [pscustomobject]@{schema=1;device=([Guid]::NewGuid().ToString('N'));name=$env:COMPUTERNAME;token='';private_key='';profile=$null}
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
    $exe = Join-Path $ExecutableDirectory 'EvgeniumCLI.exe'
    if (!(Test-Path -LiteralPath $exe)) { throw 'Не найден EvgeniumCLI.exe рядом с приложением.' }
    try { $process = Start-Process -FilePath $exe -ArgumentList @('--command', $Action, '--expected-sid', $script:Sid) -Verb RunAs -PassThru
        while (!$process.HasExited) { if ($Command -eq 'gui') { [Windows.Forms.Application]::DoEvents() }; Start-Sleep -Milliseconds 100; $process.Refresh() }
    }
    catch { throw 'Для управления VPN нужно подтвердить запрос Windows. Действие отменено.' }
    if ($process.ExitCode -ne 0) { throw 'Подключение не подтверждено. Откройте консоль: EvgeniumCLI.exe on. Интернет остаётся заблокирован, если служба туннеля запущена; кнопка «Отключить» вернёт обычную сеть.' }
    return $true
}
function Get-WireGuardPath { return (Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe') }
function Assert-WireGuardSignature([string]$Path) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=WireGuard LLC(,|$)') { throw 'Подпись WireGuard не подтверждена. Установка остановлена.' }
}
function Ensure-WireGuard {
    $exe = Get-WireGuardPath
    if (Test-Path -LiteralPath $exe) { Assert-WireGuardSignature $exe; return $exe }
    $download = Join-Path $script:Data ('wireguard-' + [Guid]::NewGuid().ToString('N') + '.msi')
    try {
        $null = Invoke-WebRequest -UseBasicParsing -Uri 'https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi' -OutFile $download -TimeoutSec 90
        Assert-WireGuardSignature $download
        $installer = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i', ('"' + $download + '"'), '/qn', '/norestart', 'DO_NOT_LAUNCH=1') -Wait -PassThru
        if ($installer.ExitCode -notin @(0,3010)) { throw 'Установщик WireGuard завершился с ошибкой.' }
        if (!(Test-Path -LiteralPath $exe)) { throw 'WireGuard не установлен. Возможно, Windows ожидает перезапуск.' }
        Assert-WireGuardSignature $exe
        return $exe
    } finally { if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Force } }
}
function Invoke-Wg([string]$Arguments, [string]$InputText = '') {
    $tool = Join-Path $env:ProgramFiles 'WireGuard\wg.exe'
    Assert-WireGuardSignature $tool
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$tool; $info.Arguments=$Arguments; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $p=New-Object Diagnostics.Process; $p.StartInfo=$info
    try {
        $null=$p.Start()
        # Binary ASCII input avoids the UTF-8 BOM inherited from a host console.
        # wg pubkey reads exactly 44 base64 bytes; a BOM corrupts that input.
        if ($InputText) { $inputBytes=[Text.Encoding]::ASCII.GetBytes($InputText+"`n"); $p.StandardInput.BaseStream.Write($inputBytes,0,$inputBytes.Length) }
        $p.StandardInput.BaseStream.Flush(); $p.StandardInput.BaseStream.Close()
        $outputTask=$p.StandardOutput.ReadToEndAsync(); $errorTask=$p.StandardError.ReadToEndAsync()
        if (!$p.WaitForExit(10000)) { $p.Kill(); throw 'WireGuard не ответил.' }
        if ($p.ExitCode -ne 0) {
            $detail=[regex]::Replace($errorTask.Result,'[A-Za-z0-9+/_-]{32,}={0,2}','[redacted]')
            if ($detail.Length -gt 300) { $detail=$detail.Substring(0,300) }
            throw ('WireGuard '+$Arguments+' завершился с кодом '+$p.ExitCode+': '+$detail.Trim())
        }; $null=$errorTask.Result; return $outputTask.Result.Trim()
    } finally { $p.Dispose() }
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
    if (!$State.private_key) { $State.private_key = Seal (Invoke-Wg 'genkey'); Save-State $State }
    $private = Unseal $State.private_key
    $public = Invoke-Wg 'pubkey' $private
    if (!(Check-Key $public)) { throw 'Не удалось создать ключ устройства.' }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    try {
        $csrf = Invoke-RestMethod -UseBasicParsing -Uri ($script:Api + '/api/session') -WebSession $session -TimeoutSec 15
        if ($csrf.csrf -notmatch '^[A-Za-z0-9_-]{20,128}$') { throw 'Неверный ответ сервера.' }
        $body = @{token=(Unseal $State.token);device=$State.device;name=$State.name;public_key=$public} | ConvertTo-Json -Compress
        $reply = Invoke-RestMethod -UseBasicParsing -Method Post -Uri ($script:Api + '/api/enroll') -WebSession $session -Headers @{'X-CSRF-Token'=$csrf.csrf} -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 25
        if (!$reply.ok) { throw 'Отказ регистрации.' }
        Validate-Profile $reply.profile
        $State.profile=$reply.profile; Save-State $State
    } catch {
        $status = 0
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -eq 401) { throw 'Токен недействителен или доступ отозван. Проверьте токен.' }
        if ($status -eq 429) { throw 'Слишком много попыток. Подождите несколько минут.' }
        throw 'Сервер регистрации недоступен или отклонил запрос. Проверьте обычный интернет и токен; повторите подключение.'
    } finally { $body=$null; $private=$null }
    return $State
}
function Assert-ServiceOwnership {
    $service=Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$script:Service+"'") -ErrorAction Stop
    if (!$service) { return }
    $exe=[regex]::Escape((Get-WireGuardPath))
    $conf=[regex]::Escape((Join-Path $script:Data 'Evgenium.conf'))
    if ($service.PathName -notmatch ('^"?'+$exe+'"?\s+/tunnelservice\s+"?'+$conf+'"?$')) { throw 'Имя Evgenium занято другим VPN-туннелем. Его настройки не изменены.' }
}
function Tunnel-Running {
    $s=Get-Service -Name $script:Service -ErrorAction SilentlyContinue
    if ($s) { Assert-ServiceOwnership }
    return ($s -and $s.Status -eq 'Running')
}
function Validate-Connection {
    # curl is told explicitly which adapter/IP to use, and not to use an HTTP proxy.
    $state=Read-State; if (!$state.profile) { return $false }; Validate-Profile $state.profile
    $address=($state.profile.address -split '/')[0]
    $curl=Join-Path $env:SystemRoot 'System32\curl.exe'
    if (!(Test-Path -LiteralPath $curl)) { throw 'Нужна актуальная Windows 10/11 с системным curl.exe для проверки VPN.' }
    $answer=& $curl --ipv4 --silent --fail --noproxy '*' --interface $address --connect-timeout 4 --max-time 8 'https://api.ipify.org' 2>$null
    if ($LASTEXITCODE -ne 0 -or ($answer -join '').Trim() -ne '38.180.164.67') { return $false }
    $answer=& $curl --ipv4 --silent --fail --noproxy '*' --interface $address --connect-timeout 4 --max-time 8 'https://discord.com/api/v10/gateway' 2>$null
    return ($LASTEXITCODE -eq 0 -and ($answer -join '') -match 'gateway.discord.gg')
}
function Connect-Vpn {
    [Console]::WriteLine('Проверяю VPN и подключение…')
    if (Invoke-Elevated 'on') { return }
    Protect-Directory $script:Data
    $wg=Ensure-WireGuard
    $existing=Get-Service -Name $script:Service -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -ne 'Running') {
        Assert-ServiceOwnership
        Start-Service -Name $script:Service
        $existing.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
    }
    if (Tunnel-Running) {
        if (Validate-Connection) { Write-Output 'Подключено через HSVDS → Эстония. IP: 38.180.164.67.'; return }
        # Keep the existing WireGuard firewall protection active on failure.
        # It already retries handshakes; reinstalling here would create a cleartext gap.
        for ($i=0; $i -lt 2; $i++) { Start-Sleep -Seconds 1; if (Validate-Connection) { Write-Output 'Соединение восстановлено через Эстонию. IP: 38.180.164.67.'; return } }
        throw 'Туннель активен, но Эстония недоступна. WireGuard продолжает восстановление и блокирует утечки. «Отключить» вернёт обычный интернет.'
    }
    $state=Enroll (Read-State)
    Validate-Profile $state.profile
    $key=Unseal $state.private_key
    if (!(Check-Key $key)) { throw 'Ключ устройства повреждён.' }
    $config="[Interface]`nPrivateKey = $key`nAddress = $($state.profile.address)`nDNS = 1.1.1.1, 1.0.0.1`nMTU = 1280`n`n[Peer]`nPublicKey = $($state.profile.public_key)`nEndpoint = 195.209.211.163:51820`nAllowedIPs = 0.0.0.0/0, ::/0`nPersistentKeepalive = 25`n"
    $file=Join-Path $script:Data 'Evgenium.conf'
    [IO.File]::WriteAllText($file, $config, (New-Object Text.UTF8Encoding($false))); $key=$null; $config=$null
    $process=Start-Process -FilePath $wg -ArgumentList @('/installtunnelservice', ('"' + $file + '"')) -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw 'WireGuard не смог запустить туннель. Повторите подключение.' }
    for ($i=0; $i -lt 4; $i++) { Start-Sleep -Milliseconds 750; if ((Tunnel-Running) -and (Validate-Connection)) { Write-Output 'Подключено через HSVDS → Эстония. IP: 38.180.164.67. DNS и Discord доступны.'; return } }
    throw 'Туннель запущен, но выход через Эстонию не подтверждён. Защита блокирует обычный трафик. Повторите «Включить» для восстановления или нажмите «Отключить».'
}
function Disconnect-Vpn {
    if (Invoke-Elevated 'off') { return }
    Assert-NoReparse $script:Data
    $wg=Get-WireGuardPath
    $service=Get-Service -Name $script:Service -ErrorAction SilentlyContinue
    if ($service) {
        Assert-ServiceOwnership
        Assert-WireGuardSignature $wg
        $process=Start-Process -FilePath $wg -ArgumentList '/uninstalltunnelservice', $script:Tunnel -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw 'Не удалось отключить туннель. Повторите попытку.' }
    }
    for ($i=0; $i -lt 20; $i++) { if (!(Get-Service -Name $script:Service -ErrorAction SilentlyContinue)) { break }; Start-Sleep -Milliseconds 250 }
    if (Get-Service -Name $script:Service -ErrorAction SilentlyContinue) { throw 'Служба ещё останавливается. Повторите отключение.' }
    $config=Join-Path $script:Data 'Evgenium.conf'; if (Test-Path -LiteralPath $config) { Remove-Item -LiteralPath $config -Force }
    Write-Output 'VPN отключён. Обычное подключение восстановлено.'
}
function Set-Token([string]$Token, [string]$Name) {
    Assert-NoReparse $script:Data
    $Token=$Token.Trim()
    $Name=$Name.Normalize([Text.NormalizationForm]::FormC).Trim()
    if ($Token -notmatch '^EVN1-[A-Za-z0-9_-]{43}$') { throw 'Ожидается полный токен EVN1-…' }
    if (!$Name.Trim() -or $Name.Length -gt 64 -or $Name -match '\p{C}') { throw 'Имя устройства должно содержать от 1 до 64 символов.' }
    if (Tunnel-Running) { throw 'Отключите VPN перед изменением токена или имени устройства.' }
    $state=Read-State
    if ($state.token -and (Unseal $state.token) -ne $Token) { $state= [pscustomobject]@{schema=1;device=([Guid]::NewGuid().ToString('N'));name=$Name;token='';private_key='';profile=$null} }
    $state.token=Seal $Token; $state.name=$Name.Trim(); Save-State $state
}
function Validate-Manifest($Manifest) {
    if ($Manifest.schema -ne 1 -or $Manifest.version -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$' -or $Manifest.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Некорректный манифест обновления.' }
    $expected='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/windows-v' + $Manifest.version + '/Evgenium-Windows-' + $Manifest.version + '-x64.zip'
    if ($Manifest.url -cne $expected) { throw 'Адрес обновления не принадлежит ожидаемому релизу Evgenium.' }
}
function Expand-VerifiedArchive([string]$Archive, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $allowed=@('Evgenium.exe','EvgeniumCLI.exe','README.txt','VERSION')
    $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -ne $allowed.Count) { throw 'Неподдерживаемая структура архива.' }
        $seen=@{}
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -cnotin $allowed -or $seen.ContainsKey($entry.FullName) -or $entry.Length -gt 8MB -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) { throw 'Небезопасная запись в архиве.' }
            $seen[$entry.FullName]=$true
        }
        $null=New-Item -ItemType Directory -Path $Destination
        foreach ($entry in $zip.Entries) { [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Destination $entry.FullName), $false) }
    } finally { $zip.Dispose() }
}
function Write-Launcher {
    $active=(Get-Content -LiteralPath (Join-Path $script:AppRoot 'current.txt') -Raw).Trim()
    if ($active -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$') { throw 'Неверная версия ярлыка.' }
    $shell=New-Object -ComObject WScript.Shell
    $shortcut=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Programs')) 'Evgenium Network.lnk'))
    $shortcut.TargetPath=Join-Path (Join-Path (Join-Path $script:AppRoot 'versions') $active) 'Evgenium.exe'; $shortcut.WorkingDirectory=$script:AppRoot; $shortcut.Save()
}
function Update-App {
    Assert-NoReparse $script:AppRoot; Protect-Directory $script:AppRoot
    $manifest=Invoke-RestMethod -UseBasicParsing -Uri $script:Manifest -TimeoutSec 20
    Validate-Manifest $manifest
    if ([version]$manifest.version -le [version]$script:Version) { Write-Output ('Установлена актуальная версия ' + $script:Version + '.'); return }
    $versions=Join-Path $script:AppRoot 'versions'; Assert-NoReparse $versions; $null=New-Item -ItemType Directory -Path $versions -Force
    $stage=Join-Path $versions ([Guid]::NewGuid().ToString('N'))
    $archive=Join-Path $script:AppRoot ([Guid]::NewGuid().ToString('N')+'.zip')
    try {
        $null=Invoke-WebRequest -UseBasicParsing -Uri $manifest.url -OutFile $archive -TimeoutSec 120
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.sha256) { throw 'Контрольная сумма обновления не совпала. Текущая версия сохранена.' }
        Expand-VerifiedArchive $archive $stage
        if ((Get-Content -LiteralPath (Join-Path $stage 'VERSION') -Raw).Trim() -cne $manifest.version) { throw 'Версия архива не совпала с манифестом.' }
        $check=Start-Process -FilePath (Join-Path $stage 'EvgeniumCLI.exe') -ArgumentList '--command','selftest' -PassThru -Wait -WindowStyle Hidden
        if ($check.ExitCode -ne 0) { throw 'Проверка новой версии не пройдена. Текущая версия сохранена.' }
        $target=Join-Path $versions $manifest.version
        if (Test-Path -LiteralPath $target) { throw 'Папка новой версии уже существует. Текущая версия сохранена.' }
        Move-Item -LiteralPath $stage -Destination $target
        # Only the small pointer is replaced after every preceding check succeeded.
        $pointer=Join-Path $script:AppRoot 'current.new'; [IO.File]::WriteAllText($pointer,$manifest.version,[Text.Encoding]::ASCII)
        Move-Item -LiteralPath $pointer -Destination (Join-Path $script:AppRoot 'current.txt') -Force
        Write-Launcher
        Write-Output ('Обновление ' + $manifest.version + ' установлено. Закройте окно и откройте Evgenium через меню «Пуск». VPN продолжает работать.')
    } finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }; if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force } }
}
function Install-App {
    $pointer=Join-Path $script:AppRoot 'current.txt'
    if (Test-Path -LiteralPath $pointer) { $current=(Get-Content -LiteralPath $pointer -Raw).Trim(); if ($current -match '^\d{1,3}\.\d{1,3}\.\d{1,3}$' -and [version]$current -gt [version]$script:Version) { Write-Output 'Уже установлена более новая версия. Откройте Evgenium из меню «Пуск».'; return } }
    Assert-NoReparse $script:AppRoot; Protect-Directory $script:AppRoot
    $versions=Join-Path $script:AppRoot 'versions'; Assert-NoReparse $versions; $null=New-Item -ItemType Directory -Path $versions -Force
    $target=Join-Path $versions $script:Version
    if ([IO.Path]::GetFullPath($target).TrimEnd('\') -ine [IO.Path]::GetFullPath($ExecutableDirectory).TrimEnd('\')) {
        if (!(Test-Path -LiteralPath $target)) {
            $stage=Join-Path $versions ([Guid]::NewGuid().ToString('N')); $null=New-Item -ItemType Directory -Path $stage
            try { foreach ($file in @('Evgenium.exe','EvgeniumCLI.exe','README.txt','VERSION')) { Copy-Item -LiteralPath (Join-Path $ExecutableDirectory $file) -Destination (Join-Path $stage $file) }; Move-Item -LiteralPath $stage -Destination $target }
            finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force } }
        }
    }
    [IO.File]::WriteAllText((Join-Path $script:AppRoot 'current.txt'),$script:Version,[Text.Encoding]::ASCII); Write-Launcher
    Write-Output 'Приложение добавлено в меню «Пуск». Токен и ключи хранятся отдельно от обновлений.'
}
function Self-Test {
    Validate-Manifest ([pscustomobject]@{schema=1;version='0.1.1';sha256=('a'*64);url='https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux/releases/download/windows-v0.1.1/Evgenium-Windows-0.1.1-x64.zip'})
    $rejected=$false; try { Validate-Manifest ([pscustomobject]@{schema=1;version='0.1.1';sha256=('a'*64);url='https://example.com/payload.zip'}) } catch { $rejected=$true }; if (!$rejected) { throw 'Unsafe URL accepted' }
    Validate-Profile ([pscustomobject]@{schema=1;public_key='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=';endpoint='195.209.211.163:51820';address='10.78.0.2/32';dns=@('1.1.1.1','1.0.0.1');mtu=1280;allowed_ips=@('0.0.0.0/0','::/0')})
    if (!(Check-Key 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=')) { throw 'Key check failed' }
    Write-Output ('Evgenium Windows ' + $script:Version + ': selftest OK')
}
function Show-Gui {
    if (!(Test-Path -LiteralPath (Join-Path $script:AppRoot 'current.txt'))) { $null=Install-App }
    Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=New-Object Windows.Forms.Form; $form.Text='Evgenium Network'; $form.ClientSize=New-Object Drawing.Size(460,570); $form.MinimumSize=$form.Size; $form.BackColor=[Drawing.Color]::FromArgb(24,21,29); $form.ForeColor=[Drawing.Color]::WhiteSmoke; $form.Font=New-Object Drawing.Font('Segoe UI',11); $form.StartPosition='CenterScreen'
    $title=New-Object Windows.Forms.Label; $title.Text='EVGENIUM'; $title.Font=New-Object Drawing.Font('Segoe UI',24,[Drawing.FontStyle]::Bold); $title.Location=New-Object Drawing.Point(24,24); $title.Size=New-Object Drawing.Size(410,48); $title.ForeColor=[Drawing.Color]::FromArgb(255,91,135); $form.Controls.Add($title)
    $connect=New-Object Windows.Forms.Button; $connect.Text='ВКЛЮЧИТЬ'; $connect.Location=New-Object Drawing.Point(24,90); $connect.Size=New-Object Drawing.Size(412,156); $connect.BackColor=[Drawing.Color]::FromArgb(196,42,85); $connect.FlatStyle='Flat'; $connect.Font=New-Object Drawing.Font('Segoe UI',22,[Drawing.FontStyle]::Bold); $form.Controls.Add($connect)
    $off=New-Object Windows.Forms.Button; $off.Text='Отключить'; $off.Location=New-Object Drawing.Point(24,256); $off.Size=New-Object Drawing.Size(200,42); $form.Controls.Add($off)
    $update=New-Object Windows.Forms.Button; $update.Text='Обновить'; $update.Location=New-Object Drawing.Point(236,256); $update.Size=New-Object Drawing.Size(200,42); $form.Controls.Add($update)
    $tokenLabel=New-Object Windows.Forms.Label; $tokenLabel.Text='Токен клиента'; $tokenLabel.Location=New-Object Drawing.Point(24,302); $tokenLabel.Size=New-Object Drawing.Size(300,20); $form.Controls.Add($tokenLabel)
    $token=New-Object Windows.Forms.TextBox; $token.Location=New-Object Drawing.Point(24,324); $token.Size=New-Object Drawing.Size(304,30); $token.UseSystemPasswordChar=$true; $form.Controls.Add($token)
    $save=New-Object Windows.Forms.Button; $save.Text='Подтвердить'; $save.Location=New-Object Drawing.Point(336,320); $save.Size=New-Object Drawing.Size(100,38); $form.Controls.Add($save)
    $nameLabel=New-Object Windows.Forms.Label; $nameLabel.Text='Имя устройства'; $nameLabel.Location=New-Object Drawing.Point(24,350); $nameLabel.Size=New-Object Drawing.Size(300,20); $form.Controls.Add($nameLabel)
    $name=New-Object Windows.Forms.TextBox; $name.Location=New-Object Drawing.Point(24,370); $name.Size=New-Object Drawing.Size(412,30); $form.Controls.Add($name)
    $status=New-Object Windows.Forms.Label; $status.Location=New-Object Drawing.Point(24,418); $status.Size=New-Object Drawing.Size(412,106); $form.Controls.Add($status)
    $version=New-Object Windows.Forms.Label; $version.Location=New-Object Drawing.Point(24,538); $version.Size=New-Object Drawing.Size(412,24); $version.Text=('Windows ' + $script:Version + ' · HSVDS → Эстония'); $form.Controls.Add($version)
    foreach ($button in @($off,$update,$save)) { $button.BackColor=[Drawing.Color]::FromArgb(59,40,54); $button.ForeColor=[Drawing.Color]::WhiteSmoke; $button.FlatStyle='Flat' }
    foreach ($inputField in @($token,$name)) { $inputField.BackColor=[Drawing.Color]::FromArgb(40,32,43); $inputField.ForeColor=[Drawing.Color]::WhiteSmoke }
    $state=Read-State; $name.Text=$state.name
    if ($state.token) { $token.Text='Токен сохранён'; $token.Enabled=$false; $save.Text='Изменить' }
    $status.Text= if (Tunnel-Running) { 'Туннель запущен. Нажмите «Включить» для проверки и автоматического восстановления.' } else { 'VPN отключён. Введите токен клиента и имя устройства.' }
    $action={ param($which)
        $connect.Enabled=$false; $off.Enabled=$false; $update.Enabled=$false; $save.Enabled=$false; $form.UseWaitCursor=$true
        $status.Text='Выполняется… Подтвердите запрос Windows, если он появится.'; [Windows.Forms.Application]::DoEvents()
        try {
            $message=switch ($which) { 'on' { Connect-Vpn } 'off' { Disconnect-Vpn } 'update' { Update-App } }
            if (!$message) { $message=if (Tunnel-Running) { 'Подключено через Эстонию. IP: 38.180.164.67.' } else { 'VPN отключён.' } }; $status.Text=($message -join "`n")
        } catch { $status.Text=$_.Exception.Message }
        finally { $connect.Enabled=$true; $off.Enabled=$true; $update.Enabled=$true; $save.Enabled=$true; $form.UseWaitCursor=$false }
    }.GetNewClosure()
    $connect.Add_Click({ & $action 'on' }.GetNewClosure()); $off.Add_Click({ & $action 'off' }.GetNewClosure()); $update.Add_Click({ & $action 'update' }.GetNewClosure())
    $save.Add_Click({
        try {
            if (!$token.Enabled) { $token.Text=Unseal ((Read-State).token); $token.Enabled=$true; $token.UseSystemPasswordChar=$false; $save.Text='Подтвердить'; return }
            Set-Token $token.Text $name.Text; $token.Text='Токен сохранён'; $token.UseSystemPasswordChar=$true; $token.Enabled=$false; $save.Text='Изменить'; $status.Text='Токен сохранён на этом устройстве. Нажмите «Включить».'
        } catch { $status.Text=$_.Exception.Message }
    }.GetNewClosure())
    [Windows.Forms.Application]::Run($form); $form.Dispose()
}
try {
    if ($ExpectedSid -and $ExpectedSid -ne $script:Sid) { throw 'UAC выполнен под другой учётной записью. Используйте ту же учётную запись Windows.' }
    if (![Environment]::Is64BitProcess) { throw 'Эта сборка предназначена для Windows x64.' }
    switch ($Command.ToLowerInvariant()) {
        'gui' { Show-Gui }
        'on' { Connect-Vpn }
        'off' { Disconnect-Vpn }
        'status' { if (Tunnel-Running) { if (Validate-Connection) { 'Подключено через Эстонию. IP: 38.180.164.67.' } else { 'Туннель запущен, доступ через Эстонию не подтверждён. EvgeniumCLI.exe on выполнит восстановление.'; $global:EvgeniumExitCode=1 } } else { 'VPN отключён.' } }
        'token' { [Console]::Write('Токен EVN1 (ввод скрыт): '); $value=''; while ($true) { $k=[Console]::ReadKey($true); if ($k.Key -eq 'Enter') { break }; if ($k.Key -eq 'Backspace') { if ($value.Length) { $value=$value.Substring(0,$value.Length-1) } } elseif (![char]::IsControl($k.KeyChar)) { $value+=$k.KeyChar } }; [Console]::WriteLine(); [Console]::Write('Имя устройства: '); Set-Token $value ([Console]::ReadLine()); $value=$null; 'Токен сохранён. EvgeniumCLI.exe on — подключиться.' }
        'update' { Update-App }
        'install' { Install-App }
        'selftest' { Self-Test }
        default { throw 'Команды: on, off, status, token, update, install, selftest.' }
    }
} catch {
    $global:EvgeniumExitCode=1
    if ($Command -eq 'gui') { Add-Type -AssemblyName System.Windows.Forms; $null=[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Evgenium') }
    else { [Console]::Error.WriteLine($_.Exception.Message) }
}
