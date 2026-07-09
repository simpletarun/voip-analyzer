; Cutter - VoIP Analyzer Installer
; Build: iscc /dAppVersion="3.2.0" installer.iss
#ifndef AppVersion
  #define AppVersion "3.2.0"
#endif

[Setup]
AppName=Cutter - VoIP Analyzer
AppVersion={#AppVersion}
AppPublisher=VoIP Analyzer Team
DefaultDirName={autopf}\Cutter
DefaultGroupName=Cutter
OutputDir=dist
OutputBaseFilename=CutterSetup-v{#AppVersion}
Compression=lzma2/normal
SolidCompression=yes
UninstallDisplayIcon={app}\cutter.exe
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "dist\cutter\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\Cutter"; Filename: "{app}\cutter.exe"
Name: "{group}\Uninstall Cutter"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Cutter"; Filename: "{app}\cutter.exe"; Tasks: desktopicon

[Run]
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S"; StatusMsg: "Installing Npcap (packet capture driver)..."; Flags: skipifdoesntexist; Check: NpcapNotInstalled
Filename: "{app}\cutter.exe"; Description: "Launch Cutter now"; Flags: postinstall nowait skipifsilent unchecked

[Code]
function NpcapNotInstalled: Boolean;
begin
  Result := not RegKeyExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst') and
            not RegKeyExists(HKLM32, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst') and
            not RegKeyExists(HKLM, 'SOFTWARE\Npcap') and
            not RegKeyExists(HKLM32, 'SOFTWARE\Npcap');
end;
