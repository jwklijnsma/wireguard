; WG2FA Windows installer (Inno Setup 6)
; iscc /DAppVersion=1.2.3 /DArch=x64 /DArchAllowed=x64compatible /DSrcDir=..\..\dist\windows-amd64 packaging\windows\wg2fa.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif
#ifndef ArchAllowed
  #define ArchAllowed "x64compatible"
#endif
#ifndef SrcDir
  #define SrcDir "..\..\dist\windows-amd64"
#endif
#ifndef OutDir
  #define OutDir "..\..\dist"
#endif

[Setup]
AppId={{6D3A1F2B-9C4E-4E8B-8F21-5A7B2C0D9E14}
AppName=WG2FA VPN
AppVersion={#AppVersion}
AppVerName=WG2FA VPN {#AppVersion}
AppPublisher=Jan Wiebe Klijnsma
AppPublisherURL=https://github.com/jwklijnsma/wireguard
DefaultDirName={autopf}\WG2FA
DefaultGroupName=WG2FA VPN
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed={#ArchAllowed}
ArchitecturesInstallIn64BitMode={#ArchAllowed}
OutputDir={#OutDir}
OutputBaseFilename=WG2FA-{#AppVersion}-windows-{#Arch}-setup
SetupIconFile=wg2fa.ico
UninstallDisplayIcon={app}\wg2fa.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Files]
Source: "{#SrcDir}\wg2fa-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "wg2fa.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\WG2FA VPN"; Filename: "{app}\wg2fa-client.exe"; Parameters: "open"; IconFilename: "{app}\wg2fa.ico"
Name: "{autodesktop}\WG2FA VPN"; Filename: "{app}\wg2fa-client.exe"; Parameters: "open"; IconFilename: "{app}\wg2fa.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\wg2fa-client.exe"; Parameters: "install"; StatusMsg: "Installing the WG2FA VPN service..."; Flags: runhidden waituntilterminated
Filename: "{app}\wg2fa-client.exe"; Parameters: "open"; Description: "Open WG2FA VPN"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{app}\wg2fa-client.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\WG2FA"

[Code]
// Stop the running service before files are replaced during an upgrade.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop WG2FA', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);
  Result := '';
end;
