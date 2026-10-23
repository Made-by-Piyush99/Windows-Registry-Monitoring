; Script generated for Windows Registry Change Monitoring System
; Publisher: MADE BY PIYUSH

#define MyAppName "Windows Registry Monitor"
#define MyAppVersion "2.4.0"
#define MyAppPublisher "MADE BY PIYUSH"
#define MyAppExeName "WindowsRegistryMonitor.exe"

[Setup]
AppId={{A17F3B24-9D61-4C82-A705-61C8D2E94015}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=dist\installer
OutputBaseFilename=RegistryMonitorSetup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=data\app_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "data\app_icon.ico"; DestDir: "{app}\data"; Flags: ignoreversion
Source: "data\baseline.json"; DestDir: "{app}\data"; Flags: ignoreversion onlyifdoesntexist

[Dirs]
Name: "{app}\data"; Permissions: authusers-modify
Name: "{app}\data\logs"; Permissions: authusers-modify
Name: "{app}\data\reports"; Permissions: authusers-modify

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\data\app_icon.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\data\app_icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall nowait skipifsilent
