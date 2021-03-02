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
#the sha is used here to pin the image that has been working correctly before

FROM microsoft/windowsservercore@sha256:10e43e24be6eb5f3e19e705a88adb9794b569028f0e0d715d40f25e53e04c3fc
 
# Download the tools
SHELL ["cmd", "/S", "/C"]
ADD "https://aka.ms/vs/15/release/vs_community.exe" "C:\TEMP\vs_community.exe"
 
# Install VS 2017 community
RUN C:\TEMP\vs_community.exe --includeRecommended --includeOptional --quiet --nocache --norestart --wait \
	--add Microsoft.VisualStudio.Workload.Python \
    || IF "%ERRORLEVEL%"=="3010" EXIT 0

WORKDIR C:/temp
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ENV CHOCO_URL=https://chocolatey.org/install.ps1
ADD https://www.python.org/ftp/python/3.9.2/Python-3.9.2.tar.xz C:/temp/

# https://github.com/pypa/get-pip
ENV PYTHON_GET_PIP_URL https://github.com/pypa/get-pip/raw/d59197a3c169cef378a22428a3fa99d33e080a5d/get-pip.py
ENV PYTHON_GET_PIP_SHA256 421ac1d44c0cf9730a088e337867d974b91bdce4ea2636099275071878cc189e
COPY python_patch/build.bat .
COPY python_patch/fips_python.patch .

RUN Set-ExecutionPolicy Bypass -Scope Process -Force; \
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'; \
  Write-Host ('Downloading get-pip.py ({0}) ...' -f $env:PYTHON_GET_PIP_URL); \
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
	Invoke-WebRequest -Uri $env:PYTHON_GET_PIP_URL -OutFile 'get-pip.py'; \
	Write-Host ('Verifying sha256 ({0}) ...' -f $env:PYTHON_GET_PIP_SHA256); \
	if ((Get-FileHash 'get-pip.py' -Algorithm sha256).Hash -ne $env:PYTHON_GET_PIP_SHA256) { \
		Write-Host 'FAILED!'; \
		exit 1; \
	}; \
  iex ((New-Object System.Net.WebClient).DownloadString("$env:CHOCO_URL")); \
  choco install git 7zip.install patch -y; \
  7z x Python-3.9.2.tar.xz; \
  7z x Python-3.9.2.tar; \
  Move-Item C:\TEMP\Python-3.9.2 C:\Python39; \
  cd C:\Python39; \
  patch -p1 -i C:\temp\fips_python.patch; \
  $env:Path += ';C:\Python39\Scripts'; \
  $env:Path += ';C:\Python39'; \
  $env:Path += ';C:\Program Files\git\bin'; \
  $bkp_path = $env:Path; \
  cmd.exe /c C:\temp\build.bat; \
  Copy-Item 'C:/Python39/PCbuild/amd64/python.exe' -Destination 'C:/Python39/PCbuild/amd64/python39.exe' -Force; \
  $env:Path = $bkp_path; \
  [Environment]::SetEnvironmentVariable('PATH', $env:Path, [System.EnvironmentVariableTarget]::Machine); \
  python --version; \
	python -m pip --version;

#Needed to just work
ENV PYTHONIOENCODING='UTF-8'
ENV _HOOK_DIR='./pkg/'
ENV NSIS_LOC='C:/Program Files (x86)/NSIS'
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
#Create location for build environment and set as working dir

WORKDIR C:/temp
VOLUME C:/data

RUN choco install git nssm -y;
RUN choco install osquery --version 4.6.0.2 -y;

#All the variables used for hubble
ARG HUBBLE_CHECKOUT=dev
ARG HUBBLE_GIT_URL=https://github.com/goravsingal/hubble.git
ENV HUBBLE_SRC_PATH='C:/temp/hubble/'
#Clone Hubble

RUN git clone "$env:HUBBLE_GIT_URL"; \
  Push-Location hubble; \
  git checkout "$env:HUBBLE_CHECKOUT"; \
  pop-location;

RUN Push-Location C:/temp/hubble/pkg/windows; \
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'; \
		./salt_build_script.ps1 -Silent;

#Copy local files to working directory
COPY hubble.conf C:/temp/

RUN Push-Location C:/temp/hubble; \
  python setup.py egg_info; \
#Use pip to install hubble dependencies
  pip install -r hubblestack.egg-info/requires.txt \
  -r optional-requirements.txt \
  -r package-requirements.txt; \
  Pop-Location;

COPY entrypoint.ps1 C:/temp/
ENV HUBBLE_CHECKOUT_ENV=$HUBBLE_CHECKOUT
ENTRYPOINT ["powershell.exe", "C:/temp/entrypoint.ps1"]
