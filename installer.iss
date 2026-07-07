[Setup]
AppName=Cutter - VoIP Analyzer
AppVersion=3.2.0
AppPublisher=VoIP Analyzer Team
DefaultDirName={autopf}\Cutter
DefaultGroupName=Cutter
OutputDir=dist
OutputBaseFilename=CutterSetup
Compression=lzma2/max
SolidCompression=yes
UninstallDisplayIcon={app}\cutter.exe
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"

[Files]
Source: "dist\cutter\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\Cutter"; Filename: "{app}\cutter.exe"
Name: "{group}\Uninstall Cutter"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Cutter"; Filename: "{app}\cutter.exe"; Tasks: desktopicon

[Run]
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S"; StatusMsg: "Installing Npcap (packet capture driver)..."; Flags: skipifdoesntexist; Check: NpcapNotInstalled

[Code]
function NpcapNotInstalled: Boolean;
begin
  Result := not RegKeyExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst') and
            not RegKeyExists(HKLM32, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst') and
            not RegKeyExists(HKLM, 'SOFTWARE\Npcap') and
            not RegKeyExists(HKLM32, 'SOFTWARE\Npcap');
end;
