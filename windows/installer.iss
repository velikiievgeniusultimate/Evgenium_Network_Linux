#ifndef AppVersion
  #error AppVersion required
#endif
#ifndef PackageDir
  #error PackageDir required
#endif
#ifndef OutputDir
  #error OutputDir required
#endif

[Setup]
AppId={{53E2495A-A134-40DC-BA91-D2FD582DE3AD}
AppName=Evgenium Network
AppVersion={#AppVersion}
AppPublisher=Evgenium Network
AppPublisherURL=https://github.com/velikiievgeniusultimate/Evgenium_Network_Linux
DefaultDirName={localappdata}\Programs\EvgeniumNetwork
UsePreviousAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
UninstallDisplayIcon={app}\Evgenium.exe
UninstallDisplayName=Evgenium Network
OutputDir={#OutputDir}
OutputBaseFilename=Evgenium-Windows-{#AppVersion}-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupMutex=Local\EvgeniumNetwork.Setup
CloseApplications=yes
CloseApplicationsFilter=Evgenium.exe,EvgeniumCLI.exe
RestartApplications=no
ChangesEnvironment=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#PackageDir}\Evgenium.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\VERSION"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Evgenium Network"; Filename: "{app}\Evgenium.exe"
Name: "{userdesktop}\Evgenium Network"; Filename: "{app}\Evgenium.exe"

[Run]
Filename: "{app}\Evgenium.exe"; Parameters: "--command post-install"; Flags: runhidden waituntilterminated; AfterInstall: CheckMigration
Filename: "{app}\Evgenium.exe"; Description: "Запустить Evgenium Network"; Flags: nowait postinstall skipifsilent; Check: ShouldLaunch
Filename: "{app}\Evgenium.exe"; Flags: nowait skipifnotsilent; Check: ShouldLaunch

[Code]
var MigrationExit: Integer;

function ShouldLaunch: Boolean;
var I: Integer;
begin
  Result := True;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/NOLAUNCH') = 0 then Result := False;
end;

function NextPart(var Value: String): Integer;
var P: Integer; Part: String;
begin
  P := Pos('.', Value);
  if P = 0 then begin Part := Value; Value := ''; end
  else begin Part := Copy(Value, 1, P-1); Delete(Value, 1, P); end;
  Result := StrToIntDef(Part, 0);
end;

function CompareVersion(A, B: String): Integer;
var I, X, Y: Integer;
begin
  Result := 0;
  for I := 1 to 3 do begin
    X := NextPart(A); Y := NextPart(B);
    if X > Y then begin Result := 1; Exit; end;
    if X < Y then begin Result := -1; Exit; end;
  end;
end;

function InitializeSetup: Boolean;
var Existing: String;
begin
  Result := True;
  if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{53E2495A-A134-40DC-BA91-D2FD582DE3AD}_is1', 'DisplayVersion', Existing) then
    if CompareVersion(Existing, '{#AppVersion}') > 0 then begin
      SuppressibleMsgBox('Уже установлена более новая версия Evgenium. Понижение версии отменено.', mbError, MB_OK, IDOK);
      Result := False;
    end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{localappdata}\Programs\EvgeniumNetwork')) <> 0 then
    Result := 'Установка поддерживается только в папку текущего пользователя.';
end;

procedure RegisterExtraCloseApplicationsResources;
var Pointer: AnsiString; Legacy: String;
begin
  if LoadStringFromFile(ExpandConstant('{localappdata}\EvgeniumNetwork\current.txt'), Pointer) then begin
    Legacy := Trim(String(Pointer));
    if (Pos('\', Legacy) = 0) and (Pos('/', Legacy) = 0) and (Pos('..', Legacy) = 0) then
      RegisterExtraCloseApplicationsResource(ExpandConstant('{localappdata}\EvgeniumNetwork\versions\') + Legacy + '\Evgenium.exe');
  end;
end;

procedure CheckMigration;
begin
  { Cleanup is best effort after the new files and uninstall registration exist.
    Private state is never removed during install/update. }
  Log('Installed GUI and registered Windows uninstaller.');
end;

function InitializeUninstall: Boolean;
var ExitCode: Integer;
begin
  Result := False;
  if CheckForMutexes('Local\EvgeniumNetwork.Desktop') then begin
    SuppressibleMsgBox('Закройте окно Evgenium и повторите удаление. VPN будет отключён самим деинсталлятором.', mbError, MB_OK, IDOK);
    Exit;
  end;
  if not FileExists(ExpandConstant('{app}\Evgenium.exe')) then begin
    SuppressibleMsgBox('Файлы Evgenium повреждены. Повторно запустите установщик для восстановления, затем удалите приложение.', mbError, MB_OK, IDOK);
    Exit;
  end;
  if not Exec(ExpandConstant('{app}\Evgenium.exe'), '--command uninstall', '', SW_SHOWNORMAL, ewWaitUntilTerminated, ExitCode) then Exit;
  if ExitCode <> 0 then begin
    SuppressibleMsgBox('Не удалось удалить туннель или настройки. Приложение сохранено; повторите удаление и подтвердите UAC.', mbError, MB_OK, IDOK);
    Exit;
  end;
  Result := True;
end;
