# Script to install hubble dependencies and create package
$chocoVer = "0.10.3"
$gitVer = "2.12.0"
$hooks = "./pkg/"

# Verify you are running with elevated permission mode (administrator token)
if (!([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))) {
    Write-Error "You must be running powershell with elevated permissions (run as administrator)"
    break
}


# Function to reload the environment
function reloadEnv() {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

#move to a better directory
if (!(Test-Path C:\temp)) {
    New-Item -Path C:\temp -ItemType Directory
}
cd c:\temp

# Install\upgrade Chocolatey and Git if not present
if (!(Test-Path C:\ProgramData\chocolatey)) {
    iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
    reloadEnv
} else {
    $chocoCur = (choco) -replace "Chocolatey v",""
    if ($chocoCur -lt $chocoVer) {
        choco upgrade choco -y
    }
}

$git = choco list --localonly | Where-Object {$_ -like "git *"}
if (!($git)) {
    choco install git -y
    reloadEnv
} else {
    if (($git -replace "git ","") -lt $gitVer) {
        choco upgrade git
    }
}

# Install salt and dependencies - including python
if (Test-Path .\Salt-Dev) {
    Remove-Item -Recurse -Force Salt-Dev
}
md Salt-Dev
pushd Salt-Dev
git clone https://github.com/saltstack/salt
cd salt\pkg\windows
git checkout 2016.11
powershell -file build_env.ps1 -Silent
popd
pushd Salt-Dev\salt
reloadEnv
python -m pip install --upgrade pip
pip install -e .
popd

# Install hubble and dependency
if (Test-Path .\hubble) {
    Remove-Item -Recurse -Force hubble
}
git clone https://github.com/hubblestack/hubble
pushd hubble\pkg\scripts
$lines = Get-Content pyinstaller-requirements.txt | Where {$_ -notmatch '^\s+$'} 
foreach ($line in $lines) {
    $line = $line -replace "#.+$",""
    if ($line -notlike '*pyinotify*' -or $line -notlike '*salt-ssh*') { #pyinotify and salt-ssh are for linux only
        pip install $line
    }
}
popd
reloadEnv

# Create pyinstaller spec
pushd hubble
pyi-makespec --additional-hooks-dir=$hooks .\hubble.py

# Edit the spec file and add libeay32.dll, C:\Python27\libeay32.dll, and BINARY
$specFile = Get-Content .\hubble.spec
$specFile = $specFile -replace "a.binaries","a.binaries + [('libeay32.dll', 'C:\Python27\libeay32.dll', 'BINARY')]"
$specFile | Set-Content .\hubble.spec -Force

# Run pyinstaller
pyinstaller .\hubble.spec