#script to build the Hubble .msi pkg
cd C:\temp

#Find the NSIS Installer
if (Test-Path "C:\Program Files\NSIS\") {
    $nsis = 'C:\Program Files\NSIS'
} Else {
    $nsis = 'C:\Program Files (x86)\NSIS'
}
If (!(Test-Path "$nsis\NSIS.exe")) {
    write-error "NSIS not found in $nsis"
    break
}

#Add NSIS to the Path
$env:Path += ";$nsis"

#Check for existing hubble pyinstall dir and removing
if (Test-Path 'C:\temp\hubble\dist') {
    Remove-Item 'C:\temp\hubble\dist' -Recurse -Force
}
if (Test-Path 'C:\temp\hubble\build') {
    Remove-Item 'C:\temp\hubble\build' -Recurse -Force
}

# Modify gitfs fix for incorrect path variables until fix has been upstreamed
$gitfsFile = Get-Content C:\Python27\Lib\site-packages\salt\utils\gitfs.py
$gitfsFile = $gitfsFile -replace "files.add(add_mountpoint(relpath(repo_path)))","files.add('/'.join(repo_path.partition('.:\\')[2].split(os.sep)))"
$gitfsFile | Set-Content C:\Python27\Lib\site-packages\salt\utils\gitfs.py -Force

# Create pyinstaller spec
pushd hubble
pyi-makespec --additional-hooks-dir=$hooks .\hubble.py

# Edit the spec file and add libeay32.dll, C:\Python27\libeay32.dll, and BINARY
$specFile = Get-Content .\hubble.spec
$specFile = $specFile -replace "a.binaries","a.binaries + [('libeay32.dll', 'C:\Python27\libeay32.dll', 'BINARY')]"
$specFile | Set-Content .\hubble.spec -Force

# Run pyinstaller
pyinstaller .\hubble.spec

Copy-Item C:\ProgramData\osquery\osqueryi.exe .\hubble\pkg\