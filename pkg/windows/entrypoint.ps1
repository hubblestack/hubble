Push-Location C:/temp/hubble;
#Create pyinstaller spec and edit it to work with windows
pyi-makespec --additional-hooks-dir=$env:_HOOK_DIR ./hubble.py;
$specFile = Get-Content -Path ./hubble.spec;
$specFile = $specFile -replace 'a.binaries','a.binaries + [(''libeay32.dll'', ''C:\Python37\libeay32.dll'', ''BINARY'')]';
Set-Content -Path ./hubble.spec -Value $specFile -Force;
pyinstaller ./hubble.spec;
Pop-Location;
#Move the hubble.conf, nssm, and osquery to the correct location
New-Item './hubble/dist/hubble/etc/hubble' -ItemType Directory;
New-Item './hubble/dist/hubble/osqueryd' -ItemType Directory;
Move-Item hubble.conf -Destination ./hubble/dist/hubble/etc/hubble/;
Move-Item 'C:/ProgramData/chocolatey/lib/NSSM/tools/nssm.exe' -Destination './hubble/dist/hubble/' -Force;
If (Test-Path C:/ProgramData/osquery/osqueryi.exe) {Copy-Item 'C:/ProgramData/osquery/osqueryi.exe' -Destination './hubble/dist/hubble/' -Force}
Else {Copy-Item 'C:/Program Files/osquery/osqueryi.exe' -Destination './hubble/dist/hubble/' -Force};
If (Test-Path C:/ProgramData/osquery/osqueryd/osqueryd.exe) {Copy-Item 'C:/ProgramData/osquery/osqueryd/osqueryd.exe' -Destination './hubble/dist/hubble/osqueryd/' -Force}
Else {Copy-Item 'C:/Program Files/osquery/osqueryd/osqueryd.exe' -Destination './hubble/dist/hubble/osqueryd/' -Force};
If (Test-Path C:/data/hubble.conf) {Copy-Item  C:/data/hubble.conf -Destination ./hubble/dist/hubble/etc/hubble/ -Force};
If (Test-Path C:/data/opt) {Copy-Item  C:/data/opt -Destination './hubble/dist/hubble/' -Recurse -Force};
Move-Item 'C:/temp/hubble/pkg/windows/osqueryd_safe_permissions.ps1' -Destination './hubble/dist/hubble/' -Force;
Move-Item 'C:/temp/hubble/pkg/windows/hubble_config_permissions.ps1' -Destination './hubble/dist/hubble/' -Force;
Move-Item 'C:/temp/hubble/pkg/windows/prerequisites.ps1' -Destination './hubble/dist/hubble/' -Force;
#Build the installer
Push-Location 'C:/Program Files (x86)/NSIS';
./makensis.exe /DHubbleVersion="$env:HUBBLE_CHECKOUT" 'C:/temp/hubble/pkg/windows/hubble-Setup.nsi';
Get-FileHash -Path C:/temp/hubble/pkg/windows/Hubble*exe -Algorithm SHA256 | Out-File C:/temp/hubble/pkg/windows/hubble_windows.sha256;
Copy-Item C:/temp/hubble/pkg/windows/Hubble*exe -Destination C:/data/;
Copy-Item C:/temp/hubble/pkg/windows/hubble_windows.sha256 -Destination C:/data/;