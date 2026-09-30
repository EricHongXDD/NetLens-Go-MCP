#ifndef AppVersion
  #define AppVersion "0.4.2"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\windows-amd64"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{327673AE-CE78-445D-8E42-80E2441B5744}
AppName=NetLens
AppVersion={#AppVersion}
AppPublisher=NetLens
AppPublisherURL=https://github.com/EricHongXDD/NetLens-Go-MCP
AppSupportURL=https://github.com/EricHongXDD/NetLens-Go-MCP/issues
DefaultDirName={localappdata}\Programs\NetLens
DefaultGroupName=NetLens
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=NetLens-{#AppVersion}-windows-amd64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayIcon={app}\NetLens.exe
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\NetLens.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\netlens-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD_PARTY_LICENSES\*"; DestDir: "{app}\THIRD_PARTY_LICENSES"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\examples\*.json"; DestDir: "{app}\examples"; Flags: ignoreversion
Source: "{#SourceDir}\docs\windows.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\NetLens"; Filename: "{app}\NetLens.exe"; WorkingDir: "{app}"; Comment: "NetLens native traffic inspector"; AppUserModelID: "NetLens.TrafficInspector"
Name: "{group}\NetLens User Data"; Filename: "{userappdata}\NetLens"
Name: "{group}\NetLens Guide"; Filename: "{app}\docs\windows.md"
Name: "{group}\Uninstall NetLens"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NetLens"; Filename: "{app}\NetLens.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\NetLens.exe"; Description: "Launch NetLens"; Flags: nowait postinstall skipifsilent

; 用户数据位于独立的 AppData 目录，升级和卸载均不删除令牌、证书和日志。
