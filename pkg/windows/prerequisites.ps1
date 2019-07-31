# Script to check if git is installed on host or not.
# If git is not installed, it'll be installed via chocolatey.
$ChocoInstalled = $false
$InstallGitCommand = "choco install git -y"

if (Get-Command git.exe -ErrorAction SilentlyContinue) {
    $GitInstalled = $true
}
else {
    if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
        $ChocoInstalled = $true
    }
    else {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex $InstallGitCommand
}