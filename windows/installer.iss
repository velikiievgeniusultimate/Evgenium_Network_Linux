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
DefaultDirName={autopf}\EvgeniumNetwork
UsePreviousAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
SetupIconFile=Assets\Evgenium.ico
UninstallDisplayIcon={app}\Evgenium.exe
UninstallDisplayName=Evgenium Network
OutputDir={#OutputDir}
OutputBaseFilename=Evgenium-Windows-{#AppVersion}-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupMutex=Global\EvgeniumNetwork.Setup
CloseApplications=no
RestartApplications=no
[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"
[Files]
Source: "{#PackageDir}\Evgenium.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\Evgenium.exe.config"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\EvgeniumEngine.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\xray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\VERSION"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PackageDir}\LICENSE-*"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{commonprograms}\Evgenium Network"; Filename: "{app}\Evgenium.exe"; IconFilename: "{app}\Evgenium.exe"; IconIndex: 0
Name: "{commondesktop}\Evgenium Network"; Filename: "{app}\Evgenium.exe"; IconFilename: "{app}\Evgenium.exe"; IconIndex: 0
[Run]
Filename: "{app}\EvgeniumEngine.exe"; Parameters: "upgrade-start"; Flags: runhidden waituntilterminated
Filename: "{app}\Evgenium.exe"; Description: "Запустить Evgenium Network"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: ShouldLaunch
Filename: "{app}\Evgenium.exe"; Flags: nowait skipifnotsilent runasoriginaluser; Check: ShouldLaunch
[Code]
var StoppedForUpgrade, Completed: Boolean;
function ShouldLaunch: Boolean;
var I: Integer;
begin
 Result := True;
 for I := 1 to ParamCount do if CompareText(ParamStr(I), '/NOLAUNCH') = 0 then Result := False;
end;
function NextPart(var Value: String): Integer;
var P: Integer; Part: String;
begin
 P := Pos('.', Value);
 if P = 0 then begin Part := Value; Value := ''; end
 else begin Part := Copy(Value,1,P-1); Delete(Value,1,P); end;
 Result := StrToIntDef(Part,0);
end;
function CompareVersion(A,B: String): Integer;
var I,X,Y: Integer;
begin
 Result := 0;
 for I := 1 to 3 do begin X := NextPart(A);Y := NextPart(B);if X>Y then begin Result:=1;Exit;end;if X<Y then begin Result:=-1;Exit;end;end;
end;
function InitializeSetup: Boolean;
var Existing: String;
begin
 Result:=True;
 if RegQueryStringValue(HKLM,'Software\Microsoft\Windows\CurrentVersion\Uninstall\{53E2495A-A134-40DC-BA91-D2FD582DE3AD}_is1','DisplayVersion',Existing) then
  if CompareVersion(Existing,'{#AppVersion}')>0 then begin SuppressibleMsgBox('Уже установлена более новая версия Evgenium. Понижение версии отменено.',mbError,MB_OK,IDOK);Result:=False;end;
end;
function CloseDesktop: Boolean;
var Code,I: Integer;
begin
 Result:=True;
 if FileExists(ExpandConstant('{app}\Evgenium.exe')) then begin
  Exec(ExpandConstant('{app}\Evgenium.exe'),'--command close-gui','',SW_HIDE,ewWaitUntilTerminated,Code);
  for I:=1 to 50 do begin if not CheckForMutexes('Local\EvgeniumNetwork.Desktop') then Exit;Sleep(100);end;
  Result:=False;
 end;
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
 Result:='';
 if CompareText(ExpandConstant('{app}'),ExpandConstant('{autopf}\EvgeniumNetwork'))<>0 then begin Result:='Приложение должно устанавливаться в защищённую системную папку.';Exit;end;
 if not CloseDesktop then begin Result:='Дождитесь завершения диагностики и закройте Evgenium.';Exit;end;
 if FileExists(ExpandConstant('{app}\EvgeniumEngine.exe')) then begin
  if not Exec(ExpandConstant('{app}\EvgeniumEngine.exe'),'upgrade-stop','',SW_HIDE,ewWaitUntilTerminated,Code) then begin Result:='Не удалось подготовить сетевую службу к обновлению.';Exit;end;
  if Code<>0 then begin Result:='Не удалось остановить свою сетевую службу. Настройки сохранены.';Exit;end;
  StoppedForUpgrade:=True;
 end;
end;
procedure CurStepChanged(CurStep: TSetupStep);
begin if CurStep=ssDone then Completed:=True;end;
procedure DeinitializeSetup;
var Code: Integer;
begin
 if StoppedForUpgrade and not Completed then Exec(ExpandConstant('{app}\EvgeniumEngine.exe'),'upgrade-start','',SW_HIDE,ewWaitUntilTerminated,Code);
end;
function InitializeUninstall: Boolean;
var Code: Integer;
begin
 Result:=False;
 if not CloseDesktop then begin SuppressibleMsgBox('Дождитесь завершения диагностики и повторите удаление.',mbError,MB_OK,IDOK);Exit;end;
 if not FileExists(ExpandConstant('{app}\Evgenium.exe')) then begin SuppressibleMsgBox('Повторно запустите установщик для восстановления файлов, затем удалите приложение.',mbError,MB_OK,IDOK);Exit;end;
 if not Exec(ExpandConstant('{app}\Evgenium.exe'),'--command uninstall','',SW_HIDE,ewWaitUntilTerminated,Code) then Exit;
 if Code<>0 then begin SuppressibleMsgBox('Не удалось удалить туннель или ключи. Приложение сохранено. Повторите удаление.',mbError,MB_OK,IDOK);Exit;end;
 Result:=True;
end;
