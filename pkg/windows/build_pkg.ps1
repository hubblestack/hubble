# Script to build the Hubble .msi pkg
cd C:\temp

$hooks = ".\pkg\"

# Find the NSIS Installer
if (Test-Path "C:\Program Files\NSIS\") {
    $nsis = 'C:\Program Files\NSIS'
} Else {
    $nsis = 'C:\Program Files (x86)\NSIS'
}
If (!(Test-Path "$nsis\NSIS.exe")) {
    write-error "NSIS not found in $nsis"
    break
}

# Add NSIS to the Path
$env:Path += ";$nsis"

# Check for existing hubble pyinstall dir and removing
if (Test-Path '.\hubble\dist') {
    Remove-Item '.\hubble\dist' -Recurse -Force
}
if (Test-Path '.\hubble\build') {
    Remove-Item '.\hubble\build' -Recurse -Force
}


# Create pyinstaller spec
pushd hubble
pyi-makespec --additional-hooks-dir=$hooks .\hubble.py

# Edit the spec file and add libeay32.dll, C:\Python27\libeay32.dll, and BINARY
$specFile = Get-Content .\hubble.spec
$modified = $gitfsFile -match 'BINARY'
if (!($modified)) {
    $specFile = $specFile -replace "a.binaries","a.binaries + [('libeay32.dll', 'C:\Python27\libeay32.dll', 'BINARY')]"
    $specFile | Set-Content .\hubble.spec -Force
}

# Run pyinstaller
pyinstaller .\hubble.spec

# Copy hubble.conf to correct location
Start-Sleep -Seconds 5
if (!(Test-Path '.\dist\hubble\etc\hubble')) {
    New-Item '.\dist\hubble\etc\hubble' -ItemType Directory
}
Copy-Item '.\pkg\windows\hubble.conf' -Destination '.\dist\hubble\etc\hubble\'

# Copy PortableGit to correct location
Copy-Item '.\PortableGit' -Destination '.\dist\hubble\' -Recurse -Force

# Copy nssm.exe to correct location
if (Test-Path '..\Salt-Dev\salt\pkg\windows\buildenv\nssm.exe') {
    Copy-Item '..\Salt-Dev\salt\pkg\windows\buildenv\nssm.exe' -Destination '.\dist\hubble\'
}

# Check for intalled osquery
if (!(Test-Path 'C:\ProgramData\osquery\osqueryi.exe')) {
	choco install osquery
}
Copy-Item C:\ProgramData\osquery\osqueryi.exe .\pkg\

# Add needed variables
$currDIR = $PWD.Path
$instDIR = $currDIR + "\pkg\windows"

# Get Prereqs vcredist
If (Test-Path "C:\Program Files (x86)") {
    Invoke-WebRequest -Uri 'http://repo.saltstack.com/windows/dependencies/64/vcredist_x64_2008_mfc.exe' -OutFile "$instDIR\vcredist.exe"
} Else {
    Invoke-WebRequest -Uri 'http://repo.saltstack.com/windows/dependencies/32/vcredist_x86_2008_mfc.exe' -OutFile "$instDIR\vcredist.exe"
}


# Build Installer
if ($version -eq $null) {
	$gitDesc = git describe
	if ($gitDesc -eq $null) {
		$version = 'Beta'
	} else {
		$version = $gitDesc
	}
}

makensis.exe /DHubbleVersion=$version "$instDIR\hubble-Setup.nsi"

Move-Item .\pkg\windows\Hubble*.exe C:\temp\


Write-Host "`n`n***************************"
Write-Host "*********Finished**********"
Write-Host "***************************"
Write-Host "`nThe Hubble installer is located in C:\temp`n`n" -ForegroundColor Yellow
