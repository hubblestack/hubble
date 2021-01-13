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
ENV _HOOK_DIR='./pkg/'
ENV NSIS_LOC='C:/Program Files (x86)/NSIS'
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
#Create location for build environment and set as working dir
RUN New-Item C:/temp -ItemType Directory; \
  New-Item C:/data -ItemType Directory;
WORKDIR C:/temp
VOLUME C:/data

#Installing Python 3.7.0
ENV PYTHON_VERSION 3.7.0
ENV PYTHON_RELEASE 3.7.0

RUN $url = ('https://www.python.org/ftp/python/{0}/python-{1}-amd64.exe' -f $env:PYTHON_RELEASE, $env:PYTHON_VERSION); \
	Write-Host ('Downloading {0} ...' -f $url); \
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
	Invoke-WebRequest -Uri $url -OutFile 'python.exe'; \
	\
	Write-Host 'Installing ...'; \
# https://docs.python.org/3.7/using/windows.html#installing-without-ui
	Start-Process python.exe -Wait \
		-ArgumentList @( \
			'/quiet', \
			'InstallAllUsers=1', \
			'TargetDir=C:\Python37', \
			'PrependPath=1', \
			'Shortcuts=0', \
			'Include_doc=0', \
			'Include_pip=0', \
			'Include_test=0' \
		); \
	\
#the installer updated PATH, so we should refresh our local value
	$env:PATH = [Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Machine); \
	\
	Write-Host 'Verifying install ...'; \
	Write-Host '  python --version'; python --version; \
	\
	Write-Host 'Removing ...'; \
	Remove-Item python.exe -Force; \
	\
	Write-Host 'Complete.'

# if this is called "PIP_VERSION", pip explodes with "ValueError: invalid truth value '<VERSION>'"
ENV PYTHON_PIP_VERSION 20.2
# https://github.com/pypa/get-pip
ENV PYTHON_GET_PIP_URL https://github.com/pypa/get-pip/raw/d59197a3c169cef378a22428a3fa99d33e080a5d/get-pip.py
ENV PYTHON_GET_PIP_SHA256 421ac1d44c0cf9730a088e337867d974b91bdce4ea2636099275071878cc189e

RUN Write-Host ('Downloading get-pip.py ({0}) ...' -f $env:PYTHON_GET_PIP_URL); \
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
	Invoke-WebRequest -Uri $env:PYTHON_GET_PIP_URL -OutFile 'get-pip.py'; \
	Write-Host ('Verifying sha256 ({0}) ...' -f $env:PYTHON_GET_PIP_SHA256); \
	if ((Get-FileHash 'get-pip.py' -Algorithm sha256).Hash -ne $env:PYTHON_GET_PIP_SHA256) { \
		Write-Host 'FAILED!'; \
		exit 1; \
	}; \
	\
	Write-Host ('Installing pip=={0} ...' -f $env:PYTHON_PIP_VERSION); \
	python get-pip.py \
		--disable-pip-version-check \
		--no-cache-dir \
		('pip=={0}' -f $env:PYTHON_PIP_VERSION) \
	; \
	Remove-Item get-pip.py -Force; \
	\
	Write-Host 'Verifying pip install ...'; \
	pip --version; \
	\
	Write-Host 'Complete.'

##install Chocolatey, then git and osquery
ENV CHOCO_URL=https://chocolatey.org/install.ps1
RUN Set-ExecutionPolicy Bypass -Scope Process -Force; \
 [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12'; \
 iex ((New-Object System.Net.WebClient).DownloadString("$env:CHOCO_URL"));
RUN choco install git nssm -y;
RUN choco install osquery --version 3.4.0 -y;

#All the variables used for hubble
ARG HUBBLE_CHECKOUT=v4.0.0
ARG HUBBLE_GIT_URL=https://github.com/hubblestack/hubble.git
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

#Get vcredist prereq for hubble
RUN $ProgressPreference = 'SilentlyContinue'; \
  Invoke-WebRequest -Uri 'http://repo.saltstack.com/windows/dependencies/64/vcredist_x64_2008_mfc.exe' -OutFile "C:/temp/hubble/pkg/windows/vcredist.exe"

COPY entrypoint.ps1 C:/temp/
ENTRYPOINT ["powershell.exe", "C:/temp/entrypoint.ps1"]