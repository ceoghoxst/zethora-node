; Zethora testnet Windows installer (Inno Setup 6). Built by the release workflow.
; Installs per user (no admin needed) into %LOCALAPPDATA%\Programs\Zethora, which
; is writable, so the app can keep its logs and the miner key file there.
; Uninstalling removes only the files installed here: the key file and logs are
; never deleted, so rewards are not lost by uninstalling.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6E0B7C1A-3D7E-4C2B-9F4E-2E7A0B5C9D13}
AppName=Zethora (testnet)
AppVersion={#AppVersion}
AppPublisher=DeionRaven Labs (project name, not a registered company)
AppPublisherURL=https://github.com/ceoghoxst/zethora-node
DefaultDirName={userpf}\Zethora
DefaultGroupName=Zethora
PrivilegesRequired=lowest
DisableProgramGroupPage=yes
OutputDir=..
OutputBaseFilename=Zethora-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
LicenseFile=..\bin\LICENSE.txt
WizardStyle=modern
UninstallDisplayName=Zethora (testnet)

[Files]
Source: "..\bin\*"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\Zethora"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\Zethora.ps1"""; WorkingDir: "{app}"; Comment: "Zethora testnet miner"
Name: "{group}\Zethora"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\Zethora.ps1"""; WorkingDir: "{app}"; Comment: "Zethora testnet miner"
Name: "{group}\Zethora folder (key file and logs)"; Filename: "{app}"
Name: "{group}\Read me"; Filename: "{app}\README.txt"
Name: "{group}\Uninstall Zethora"; Filename: "{uninstallexe}"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\Zethora.ps1"""; WorkingDir: "{app}"; Description: "Open Zethora now"; Flags: postinstall nowait skipifsilent
