# Load parameters
param(
    [switch]$Silent,
    [switch]$NoPipDependencies
)

#==============================================================================
# Get the Directory of actual script
#==============================================================================
$script_path = dir "$($myInvocation.MyCommand.Definition)"
$script_path = $script_path.DirectoryName

#==============================================================================
# Get the name of actual script
#==============================================================================
$script_name = $MyInvocation.MyCommand.Name

Write-Output "================================================================="
Write-Output ""
Write-Output "               Development Environment Installation"
Write-Output ""
Write-Output "               - Installs All Salt Dependencies"
Write-Output "               - Detects 32/64 bit Architectures"
Write-Output ""
Write-Output "               To run silently add -Silent"
Write-Output "               eg: ${script_name} -Silent"
Write-Output ""
Write-Output "               To run skip installing pip dependencies add -NoPipDependencies"
Write-Output "               eg: ${script_name} -NoPipDependencies"
Write-Output ""
Write-Output "================================================================="
Write-Output ""

#==============================================================================
# Import Modules
#==============================================================================
Import-Module $script_path\Modules\download-module.psm1
Import-Module $script_path\Modules\get-settings.psm1
Import-Module $script_path\Modules\uac-module.psm1
# Import-Module $script_path\Modules\zip-module.psm1
Import-Module $script_path\Modules\start-process-and-test-exitcode.psm1
#==============================================================================
# Check for Elevated Privileges
#==============================================================================
If (!(Get-IsAdministrator)) {
    If (Get-IsUacEnabled) {
        # We are not running "as Administrator" - so relaunch as administrator
        # Create a new process object that starts PowerShell
        $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";

        # Specify the current script path and name as a parameter
        $newProcess.Arguments = $myInvocation.MyCommand.Definition

        # Specify the current working directory
        $newProcess.WorkingDirectory = "$script_path"

        # Indicate that the process should be elevated
        $newProcess.Verb = "runas";

        # Start the new process
        [System.Diagnostics.Process]::Start($newProcess);

        # Exit from the current, unelevated, process
        Exit
    } Else {
        Throw "You must be administrator to run this script"
    }
}

#------------------------------------------------------------------------------
# Load Settings
#------------------------------------------------------------------------------
$ini = Get-Settings

#------------------------------------------------------------------------------
# Create Directories
#------------------------------------------------------------------------------
$p = New-Item $ini['Settings']['DownloadDir'] -ItemType Directory -Force
$p = New-Item "$($ini['Settings']['DownloadDir'])\64" -ItemType Directory -Force
$p = New-Item "$($ini['Settings']['DownloadDir'])\32" -ItemType Directory -Force

#------------------------------------------------------------------------------
# Determine Architecture (32 or 64 bit) and assign variables
#------------------------------------------------------------------------------
If ([System.IntPtr]::Size -ne 4) {
    Write-Output "Detected 64bit Architecture..."

    $bitDLLs     = "64bitDLLs"
    $bitPaths    = "64bitPaths"
    $bitPrograms = "64bitPrograms"
    $bitFolder   = "64"
} Else {
    Write-Output "Detected 32bit Architecture"
    $bitDLLs     = "32bitDLLs"
    $bitPaths    = "32bitPaths"
    $bitPrograms = "32bitPrograms"
    $bitFolder   = "32"
}

#------------------------------------------------------------------------------
# Check for installation of NSIS
#------------------------------------------------------------------------------
Write-Output " - Checking for NSIS installation . . ."
If (Test-Path "$($ini[$bitPaths]['NSISDir'])\NSIS.exe") {
    # Found NSIS, do nothing
    Write-Output " - NSIS Found . . ."
} Else {
    # NSIS not found, install
    Write-Output " - NSIS Not Found . . ."
    Write-Output " - Downloading $($ini['Prerequisites']['NSIS']) . . ."
    $file = "$($ini['Prerequisites']['NSIS'])"
    $url  = "$($ini['Settings']['SaltRepo'])/$file"
    $file = "$($ini['Settings']['DownloadDir'])\$file"
    DownloadFileWithProgress $url $file

    # Install NSIS
    Write-Output " - Installing $($ini['Prerequisites']['NSIS']) . . ."
    $file = "$($ini['Settings']['DownloadDir'])\$($ini['Prerequisites']['NSIS'])"
    $p    = Start-Process $file -ArgumentList '/S' -Wait -NoNewWindow -PassThru
}

#------------------------------------------------------------------------------
# Check for installation of Microsoft Visual C++ Build Tools
#------------------------------------------------------------------------------
Write-Output " - Checking for Microsoft Visual C++ Build Tools installation . . ."
If (Test-Path "$($ini[$bitPaths]['VCppBuildToolsDir'])\vcbuildtools.bat") {
    # Found Microsoft Visual C++ Build Tools, do nothing
    Write-Output " - Microsoft Visual C++ Build Tools Found . . ."
} Else {
    # Microsoft Visual C++ Build Tools not found, install
    Write-Output " - Microsoft Visual C++ Build Tools Not Found . . ."
    Write-Output " - Downloading $($ini['Prerequisites']['VCppBuildTools']) . . ."
    $file = "$($ini['Prerequisites']['VCppBuildTools'])"
    $url  = "$($ini['Settings']['SaltRepo'])/$file"
    $file = "$($ini['Settings']['DownloadDir'])\$file"
    DownloadFileWithProgress $url $file

    # Install Microsoft Visual C++ Build Tools
    Write-Output " - Installing $($ini['Prerequisites']['VCppBuildTools']) . . ."
    $file = "$($ini['Settings']['DownloadDir'])\$($ini['Prerequisites']['VCppBuildTools'])"
    $p    = Start-Process $file -ArgumentList '/Quiet' -Wait -NoNewWindow -PassThru
}


#------------------------------------------------------------------------------
# Update Environment Variables
#------------------------------------------------------------------------------
Write-Output " - Updating Environment Variables . . ."
$Path = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
If (!($Path.ToLower().Contains("$($ini['Settings']['Scripts3Dir'])".ToLower()))) {
    $newPath  = "$($ini['Settings']['Scripts3Dir']);$Path"
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
    $env:Path = $newPath
}


#==============================================================================
# Install windows specific pypi resources using pip
#    caching depends on environment variable SALT_REQ_LOCAL_CACHE
#==============================================================================
Write-Output " ----------------------------------------------------------------"
Write-Output " - $script_name :: Installing windows specific pypi resources using pip . . ."
Write-Output " ----------------------------------------------------------------"
if ( ! [bool]$Env:SALT_REQ_LOCAL_CACHE) {
    Start_Process_and_test_exitcode "cmd" "/c $($ini['Settings']['Python3Dir'])\python.exe -m pip --disable-pip-version-check --no-cache-dir install -r $($script_path)\req_win.txt" "pip install"
} else {
    if ( (Get-ChildItem $Env:SALT_REQ_LOCAL_CACHE | Measure-Object).Count -eq 0 ) {
        # folder empty
        Write-Output "    pip download from req_win.txt into empty local cache SALT_REQ $Env:SALT_REQ_LOCAL_CACHE"
        Start_Process_and_test_exitcode "cmd" "/c $($ini['Settings']['Python3Dir'])\python.exe -m pip --disable-pip-version-check download --dest $Env:SALT_REQ_LOCAL_CACHE -r $($script_path)\req_win.txt" "pip download"
    }
    Write-Output "    reading from local pip cache $Env:SALT_REQ_LOCAL_CACHE"
    Write-Output "    If a (new) resource is missing, please delete all files in this cache, go online and repeat"
  Start_Process_and_test_exitcode "cmd" "/c $($ini['Settings']['Python3Dir'])\python.exe -m pip --disable-pip-version-check install --no-index --find-links=$Env:SALT_REQ_LOCAL_CACHE -r $($script_path)\req_win.txt" "pip install"
}

#==============================================================================
# Install pypi resources using pip
#    caching depends on environment variable SALT_REQ_LOCAL_CACHE
#==============================================================================
If ($NoPipDependencies -eq $false) {
  Write-Output " ----------------------------------------------------------------"
  Write-Output " - $script_name :: Installing pypi resources using pip . . ."
  Write-Output " ----------------------------------------------------------------"
  if ( ! [bool]$Env:SALT_REQ_LOCAL_CACHE) {
      Start_Process_and_test_exitcode "cmd" "/c $($ini['Settings']['Python3Dir'])\python.exe -m pip --disable-pip-version-check --no-cache-dir install -r $($script_path)\req.txt" "pip install"
  } else {
      if ( (Get-ChildItem $Env:SALT_REQ_LOCAL_CACHE | Measure-Object).Count -eq 0 ) {
          # folder empty
          Write-Output "    pip download from req.txt into empty local cache SALT_REQ $Env:SALT_REQ_LOCAL_CACHE"
          Start_Process_and_test_exitcode "cmd" "/c $($ini['Settings']['Python3Dir'])\python.exe -m pip --disable-pip-version-check download --dest $Env:SALT_REQ_LOCAL_CACHE -r $($script_path)\req.txt" "pip download"
      }
      Write-Output "    reading from local pip cache $Env:SALT_REQ_LOCAL_CACHE"
      Write-Output "    If a (new) resource is missing, please delete all files in this cache, go online and repeat"
    Start_Process_and_test_exitcode "cmd" "/c $($ini['Settings']['Python3Dir'])\python.exe -m pip --disable-pip-version-check install --no-index --find-links=$Env:SALT_REQ_LOCAL_CACHE -r $($script_path)\req.txt" "pip install"
  }
}

#==============================================================================
# Cleaning Up PyWin32
#==============================================================================
Write-Output " ----------------------------------------------------------------"
Write-Output " - $script_name :: Cleaning Up PyWin32 . . ."
Write-Output " ----------------------------------------------------------------"

# Move DLL's to Python Root
# The dlls have to be in Python directory and the site-packages\win32 directory
Write-Output " - $script_name :: Moving PyWin32 DLLs . . ."
Copy-Item "$($ini['Settings']['SitePkgs3Dir'])\pywin32_system32\*.dll" "$($ini['Settings']['Python3Dir'])" -Force
Move-Item "$($ini['Settings']['SitePkgs3Dir'])\pywin32_system32\*.dll" "$($ini['Settings']['SitePkgs3Dir'])\win32" -Force

# Create gen_py directory
Write-Output " - $script_name :: Creating gen_py Directory . . ."
New-Item -Path "$($ini['Settings']['SitePkgs3Dir'])\win32com\gen_py" -ItemType Directory -Force | Out-Null

# Remove pywin32_system32 directory
Write-Output " - $script_name :: Removing pywin32_system32 Directory . . ."
Remove-Item "$($ini['Settings']['SitePkgs3Dir'])\pywin32_system32"

# Remove pythonwin directory
Write-Output " - $script_name :: Removing pythonwin Directory . . ."
Remove-Item "$($ini['Settings']['SitePkgs3Dir'])\pythonwin" -Force -Recurse

# Remove PyWin32 PostInstall and testall Scripts
Write-Output " - $script_name :: Removing PyWin32 scripts . . ."
Remove-Item "$($ini['Settings']['Scripts3Dir'])\pywin32_*" -Force -Recurse


#==============================================================================
# Copy DLLs to Python Directory
#==============================================================================
Write-Output " ----------------------------------------------------------------"
Write-Output "   - $script_name :: Copying DLLs . . ."
Write-Output " ----------------------------------------------------------------"
# Architecture Specific DLL's
ForEach($key in $ini[$bitDLLs].Keys) {
    Write-Output "   - $key . . ."
    $file = "$($ini[$bitDLLs][$key])"
    $url  = "$($ini['Settings']['SaltRepo'])/$bitFolder/$file"
    $file = "$($ini['Settings']['DownloadDir'])\$bitFolder\$file"
    DownloadFileWithProgress $url $file
    Copy-Item $file  -destination $($ini['Settings']['Python3Dir'])
}

#------------------------------------------------------------------------------
# Script complete
#------------------------------------------------------------------------------
Write-Output "================================================================="
Write-Output " $script_name :: Salt Stack Dev Environment Script Complete"
Write-Output "================================================================="
Write-Output ""

If (-Not $Silent) {
    Write-Output "Press any key to continue ..."
    $p = $HOST.UI.RawUI.Flushinputbuffer()
    $p = $HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

#------------------------------------------------------------------------------
# Remove the temporary download directory
#------------------------------------------------------------------------------
Write-Output " ----------------------------------------------------------------"
Write-Output " - $script_name :: Cleaning up downloaded files unless you use SALTREPO_LOCAL_CACHE"
Write-Output " ----------------------------------------------------------------"
Write-Output ""
if ( ! [bool]$Env:SALTREPO_LOCAL_CACHE ) {
    Remove-Item $($ini['Settings']['DownloadDir']) -Force -Recurse
}