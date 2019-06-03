# This Dockerfile aims to make building Hubble v2 packages easier.
# If you don't have docker installed on your server/workstation please run setup_docker_env.ps1
# To build an image: 1. copy pkg/windows/pyinstaller-requirements.txt &  to directory with this Dockerfile
#                    2. docker build -t <image_name> .
# The resulting image is ready to run the pyinstaller on container start and drop hubble<version>.exe
# in a local directory. Mount c:\data volume into a directory on the host to access the package.
# To run the container:  
#                    3. Copy over any other items you want to include with hubble and place them in <host folder>/opt
#                    4. docker run -it --rm -v <host folder>:c:\data <image_name>
#build docker image from windowscore
FROM microsoft/windowsservercore:ltsc2016
#Needed to just work
ENV PYTHONIOENCODING='UTF-8'
ENV CHOCO_URL=https://chocolatey.org/install.ps1
#All the variables used for salt
ENV SALT_SRC_PATH='C:/temp/salt/'
ENV SALT_GIT_URL=https://github.com/saltstack/salt
ENV SALT_CHECKOUT=v2018.11
#All the variables used for hubble
ARG HUBBLE_CHECKOUT=v3.0.1
ARG HUBBLE_GIT_URL=https://github.com/hubblestack/hubble.git
ENV HUBBLE_SRC_PATH='C:/temp/hubble/'
ENV _HOOK_DIR='./pkg/'
ENV NSIS_LOC='C:/Program Files (x86)/NSIS'
#Create location for build environment and set as working dir
RUN powershell.exe -Command New-Item c:/temp -ItemType Directory; \
  New-Item C:/data -ItemType Directory;
WORKDIR C:/temp
VOLUME C:/data
#Copy local files to working directory
COPY pyinstaller-requirements.txt c:/temp/
COPY hubble.conf C:/temp/
#install Chocolatey, then git and git.portable, and osquery
RUN powershell.exe -Command Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString("$env:CHOCO_URL"))
RUN powershell.exe -Command choco install git nssm -y;
RUN powershell.exe -Command choco install osquery --version 3.3.2 -y;
RUN powershell.exe -Command choco install git.portable --version 2.19.0 -y;

#RUN powershell.exe $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
#Git clone salt and run packages
RUN powershell.exe -Command git clone "$env:SALT_GIT_URL"; \
  Push-Location salt/pkg/windows; \
  git checkout "$env:SALT_CHECKOUT"; \
  C:/temp/salt/pkg/windows/build_env_2.ps1 -Silent;
#more salt installs
RUN powershell.exe -Command Push-Location salt; \
  test-path ./setup.py; \
  python ./setup.py --quiet install --force; \
  pop-location;
#Clone Hubble
RUN powershell.exe -Command git clone "$env:HUBBLE_GIT_URL"; \
  Push-Location hubble; \
  git checkout "$env:HUBBLE_CHECKOUT"; \
  pop-location;
  
#Use pip to install hubble dependencies
RUN powershell.exe -Command pip install -r pyinstaller-requirements.txt;
  
#Move portable git to a new location
RUN powershell.exe -Command New-Item C:/temp/hubble/PortableGit -ItemType Directory; \
  Copy-Item -Path C:/tools/git/* -Destination C:/temp/hubble/PortableGit/ -Recurse;
  
# Modify gitfs fix for incorrect path variables until fix has been upstreamed
RUN powershell.exe -Command If (!(Test-Path C:/Python27/Lib/site-packages/salt)) {Copy-Item C:/temp/salt/salt -Destination C:/Python27/Lib/site-packages/ -Recurse -Force}; \
  $gitfsFile = Get-Content C:\Python27\Lib\site-packages\salt\utils\gitfs.py; \
  $gitfsFile = $gitfsFile -replace 'files.add\\(add_mountpoint\\(relpath\\(repo_path\\)\\)\\)','files.add("/".join(repo_path.partition(".:\\")[2].split(os.sep)))'; \
  Set-Content -Path C:\Python27\Lib\site-packages\salt\utils\gitfs.py -Value $gitfsFile -Force
#Get vcredist prereq for hubble
RUN powershell.exe -Command \
  $ProgressPreference = 'SilentlyContinue'; \ 
  Invoke-WebRequest -Uri 'http://repo.saltstack.com/windows/dependencies/64/vcredist_x64_2008_mfc.exe' -OutFile "C:/temp/hubble/pkg/windows/vcredist.exe"
#Create pyionstaller spec and edit it to work with windows
CMD powershell.exe -Command Push-Location C:/temp/hubble; \
  pyi-makespec --additional-hooks-dir=$env:_HOOK_DIR ./hubble.py; \
  $specFile = Get-Content 'C:/temp/hubble/hubble.spec'; \
  $specFile = $specFile -replace 'a.binaries','a.binaries + [(''libeay32.dll'', ''C:\Python27\libeay32.dll'', ''BINARY'')]'; \
  Set-Content -Path ./hubble.spec -Value $specFile -Force; \
  pyinstaller ./hubble.spec; \
  Pop-Location; \
#Move the hubble.conf, PortableGit, nssm, and osquery to the corerect location
  New-Item './hubble/dist/hubble/etc/hubble' -ItemType Directory; \
  New-Item './hubble/dist/hubble/osqueryd' -ItemType Directory; \
  Move-Item hubble.conf -Destination ./hubble/dist/hubble/etc/hubble/; \
  Move-Item 'hubble/PortableGit' -Destination './hubble/dist/hubble/' -Force; \
  Move-Item 'C:/ProgramData/chocolatey/lib/NSSM/tools/nssm.exe' -Destination './hubble/dist/hubble/' -Force; \
  Move-Item 'C:/ProgramData/osquery/osqueryi.exe' -Destination './hubble/dist/hubble/' -Force; \
  Move-Item 'C:/ProgramData/osquery/osqueryd/osqueryd.exe' -Destination './hubble/dist/hubble/osqueryd/' -Force; \
  If (Test-Path C:/data/hubble.conf) {Copy-Item  C:/data/hubble.conf -Destination ./hubble/dist/hubble/etc/hubble/ -Force}; \
  If (Test-Path C:/data/opt) {Copy-Item  C:/data/opt -Destination './hubble/dist/hubble/' -Recurse -Force}; \
  Move-Item 'C:/temp/hubble/pkg/windows/osqueryd_safe_permissions.ps1' -Destination './hubble/dist/hubble/' -Force; \
#Build the installer
  Push-Location 'C:/Program Files (x86)/NSIS'; \
  ./makensis.exe /DHubbleVersion="$env:HUBBLE_CHECKOUT" 'C:/temp/hubble/pkg/windows/hubble-Setup.nsi'; \
  Get-FileHash -Path C:/temp/hubble/pkg/windows/Hubble*exe -Algorithm SHA256 ^| Out-File C:/temp/hubble/pkg/windows/hubble_windows.sha256; \
  Copy-Item C:/temp/hubble/pkg/windows/Hubble*exe -Destination C:/data/; \
  Copy-Item C:/temp/hubble/pkg/windows/hubble_windows.sha256 -Destination C:/data/; 
  
