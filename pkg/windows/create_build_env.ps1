# Script to install hubble dependencies and create executible
$chocoVer = "0.10.5"
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
    $chocoCur = (choco)[0] -replace "Chocolatey v",""
    if ($chocoCur -lt $chocoVer) {
        choco upgrade chocolatey -y
    }
}

$git = choco list --localonly | Where-Object {$_ -like "git *"}
if (!($git)) {
    choco install git -y
    reloadEnv
} else {
    if (($git -replace "git ","") -lt $gitVer) {
        choco upgrade git -y
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
git checkout v2016.11.3
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
    if ($line -notlike '*pyinotify*' -and $line -notlike '*salt-ssh*') { #pyinotify and salt-ssh are for linux only
        pip install $line
    }
}
popd

# Install osquery for executible
if (!(Test-path C:\ProgramData\osquery)) {
	choco install osquery -y
} else {
	choco update osquery -y
}
reloadEnv

# Modify gitfs fix for incorrect path variables until fix has been upstreamed
if (!(Test-Path C:\Python27\Lib\site-packages\salt)) {
    Copy-Item .\Salt-Dev\salt\salt -Destination C:\Python27\Lib\site-packages\ -Recurse -Force
}

$gitfsFile = Get-Content C:\Python27\Lib\site-packages\salt\utils\gitfs.py
$gitfsFile = $gitfsFile -replace "files.add\(add_mountpoint\(relpath\(repo_path\)\)\)","files.add('/'.join(repo_path.partition('.:\\')[2].split(os.sep)))"
$gitfsFile | Set-Content C:\Python27\Lib\site-packages\salt\utils\gitfs.py -Force

#Remove obligitory c:\salt directory if it was created during script run
if (Test-Path C:\salt) {
    $empty = Get-ChildItem C:\salt
    if ($empty -eq $null) {
        Remove-Item C:\salt
    }
}