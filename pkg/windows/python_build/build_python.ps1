if (!(Test-Path 'C:\python_dev')) {
  New-Item 'C:\python_dev' -ItemType Directory
}
if (!(Test-Path 'C:\buildtools')) {
  New-Item 'C:\buildtools' -ItemType Directory
}

${Env:ProgramFiles(x86)}= "C:\Program Files (x86)"
echo ${Env:ProgramFiles(x86)}

Copy-Item 'build.bat' -Destination 'C:\python_dev\build.bat' -Force
Copy-Item 'fips_python.patch' -Destination 'C:\python_dev\fips_python.patch' -Force

Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'
Write-Host ('Downloading VS Installer...')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://aka.ms/vs/15/release/vs_community.exe -OutFile 'C:\python_dev\vs_community.exe'

Write-Host ('Installing Visual Studio 2017 Community Edition...')
$process = Start-Process -FilePath C:\python_dev\vs_Community.exe -ArgumentList "--includeRecommended", "--includeOptional", "--quiet", "--nocache", "--norestart", "--wait", "--installPath", "c:\buildtools", "--add", "Microsoft.VisualStudio.Workload.Python", "--add", "Microsoft.ComponentGroup.PythonTools.NativeDevelopment", "--add", "Microsoft.Component.MSBuild", "--add", "Component.CPython3.x86" -Wait -PassThru
Write-Output $process.ExitCode

Write-Host ('Installing Choco...')
iex ((New-Object System.Net.WebClient).DownloadString("https://chocolatey.org/install.ps1"));

# choco install git 7zip.install -y;
cd C:\python_dev

if ((Test-Path 'C:\Python39')) {
  # Cleanup
  Remove-Item C:\Python39 -Recurse
}
if ((Test-Path 'C:\python_dev\Python-3.9.2')) {
  # Cleanup
  Remove-Item C:\python_dev\Python-3.9.2 -Recurse
}

if (!(Test-Path 'C:\python_dev\Python-3.9.2.tar.xz')) {
  Write-Host ('Downloading python...')
  Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.9.2/Python-3.9.2.tar.xz -OutFile 'C:\python_dev\Python-3.9.2.tar.xz'
}

Write-Host ('Untar Python...')
7z x Python-3.9.2.tar.xz
7z x Python-3.9.2.tar
Move-Item C:\python_dev\Python-3.9.2 C:\Python39

cd C:\Python39
cmd.exe /c "c:\Program Files\Git\usr\bin\patch.exe" -p1 -i C:\python_dev\fips_python.patch
Write-Host ('Patch success...')

Write-Host ('Building Python...')
cmd.exe /c C:\python_dev\build.bat
Write-Host ('Build Python success...')

Copy-Item 'C:\Python39\PCbuild\amd64\python.exe' -Destination 'c:\Python39\PCbuild\amd64\python39.exe' -Force
Write-Host ('Done...')
