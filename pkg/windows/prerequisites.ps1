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
		$securityProtocolSettingsOriginal = [System.Net.ServicePointManager]::SecurityProtocol

		try {
		  # This should work in .NET 4 where .NET 4.5 is installed as an inplace upgrade
		  # Set TLS1.2 (3072) then TLS1.1 (768), then TLS 1.0 (192), finally SSL3 (48)
		  $securityProtocolSettings = 3072 -bor 768 -bor 192 -bor 48 
		  [System.Net.ServicePointManager]::SecurityProtocol = $securityProtocolSettings
		} catch {
		  Write-Warning "Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. Please upgrade to at least .NET Framework 4.5 and PowerShell v3 for this to work appropriately."
		}
		Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
		[System.Net.ServicePointManager]::SecurityProtocol = $securityProtocolSettingsOriginal
    }
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex $InstallGitCommand
}