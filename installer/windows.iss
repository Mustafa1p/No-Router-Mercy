#ifndef AppVersion
  #error AppVersion must be supplied by scripts/package-windows.ps1
#endif
#ifndef AppArch
  #error AppArch must be x86 or x64
#endif
#ifndef BinaryPath
  #error BinaryPath must point to the compiled application
#endif
#ifndef ReleaseDir
  #error ReleaseDir must be an absolute output folder
#endif

[Setup]
AppId={{93D83EF6-0D17-41DF-895C-25A5117AD4C1}-{#AppArch}
AppName=No Router-Mercy
AppVersion={#AppVersion}
AppPublisher=No Router-Mercy contributors
AppPublisherURL=https://github.com/Mustafa1p/No-Router-Mercy
AppSupportURL=https://github.com/Mustafa1p/No-Router-Mercy/issues
DefaultDirName={localappdata}\Programs\No Router-Mercy {#AppArch}
DefaultGroupName=No Router-Mercy {#AppArch}
PrivilegesRequired=lowest
MinVersion=10.0
UninstallDisplayIcon={app}\no-router-mercy.exe
SetupIconFile=..\src-media\logo.ico
OutputDir={#ReleaseDir}
OutputBaseFilename=No-Router-Mercy-{#AppVersion}-windows-{#AppArch}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
#if AppArch == "x64"
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#else
ArchitecturesAllowed=x86compatible
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#BinaryPath}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\CONTRIBUTING.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\examples\*"; DestDir: "{app}\examples"; Flags: ignoreversion recursesubdirs
Source: "..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs
Source: "..\src-media\app-icon.png"; DestDir: "{app}\src-media"; Flags: ignoreversion

[Icons]
Name: "{group}\No Router-Mercy"; Filename: "{app}\no-router-mercy.exe"
Name: "{autodesktop}\No Router-Mercy {#AppArch}"; Filename: "{app}\no-router-mercy.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\no-router-mercy.exe"; Description: "Launch No Router-Mercy"; Flags: nowait postinstall skipifsilent
