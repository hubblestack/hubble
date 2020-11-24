;HubbleStack Installer
;Install Hubble with Index, Indexer, and Token options
;Written by Chad Mills

;--------------------------------
!define PRODUCT_NAME "Hubble"
!define PRODUCT_NAME_OTHER "HubbleStack"
!define PRODUCT_PUBLISHER "Adobe, Inc"
!define PRODUCT_WEB_SITE "https://hubblestack.io/"
!define PRODUCT_CALL_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\hubble.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_KEY_OTHER "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME_OTHER}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

# Import Libraries
!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "StrFunc.nsh"
!include "x64.nsh"
!include "WinMessages.nsh"
!include "WinVer.nsh"

!ifdef HubbleVersion
    !define PRODUCT_VERSION "${HubbleVersion}"
!else
    !define PRODUCT_VERSION "Undefined Version"
!endif

!if "$%PROCESSOR_ARCHITECTURE%" == "AMD64"
    !define CPUARCH "AMD64"
	!define PFILES "Program Files (x86)"
!else if "$%PROCESSOR_ARCHITEW6432%" == "AMD64"
    !define CPUARCH "AMD64"
	!define PFILES "Program Files (x86)"
!else
    !define CPUARCH "x86"
	!define PFILES "Program Files"
!endif



;--------------------------------
;General
  ;Name and File
  Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
  OutFile "Hubble-${PRODUCT_VERSION}-Setup.exe"

  ;Default Installation folder
  InstallDir "C:\${PFILES}\Hubble"

  ;Get installation folder from registry if available
  InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
  ShowInstDetails show
  ShowUnInstDetails show

  ;Request application privileges for Windows Vista
  RequestExecutionLevel highest

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING
  !define MUI_ICON "hubble.ico"
  !define MUI_UNICON "hubble.ico"
  ;!define MUI_WELCOMEFINISHPAGE_BITMAP "panel.bmp"


;--------------------------------
;Pages

  ; Welcome page
  !insertmacro MUI_PAGE_WELCOME

  ; License page
  !insertmacro MUI_PAGE_LICENSE "LICENSE.txt"

  ; Configure Hubble page
  Page custom pageHubbleConfig pageHubbleConfig_Leave

  ; Instfiles page
  !insertmacro MUI_PAGE_INSTFILES

  ; Finish page (Customized)
  !define MUI_PAGE_CUSTOMFUNCTION_SHOW pageFinish_Show
  !define MUI_PAGE_CUSTOMFUNCTION_LEAVE pageFinish_Leave
  !insertmacro MUI_PAGE_FINISH

  ; Uninstaller pages
  !insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
;Languages

  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Custom Dialog Box Variables
  Var Dialog
  Var Label
  Var CheckBox_Hubble_Start
  Var CheckBox_Hubble_Start_Delayed
  Var HECToken
  Var HECToken_State
  Var IndexName
  Var IndexName_State
  Var Indexer
  Var Indexer_State
  Var StartHubble
  Var StartHubbleDelayed
  Var DeleteInstallDir

;--------------------------------
;Hubble Settings Dialog Box

  Function pageHubbleConfig

    # Set Page Title and Description
    !insertmacro MUI_HEADER_TEXT "Hubble Settings" "Set the Token and Index for Splunk (Click Next to Skip)"
    nsDialogs::Create 1018
    Pop $Dialog

    ${If} $Dialog == error
        Abort
    ${EndIf}

    ${NSD_CreateLabel} 0 0 100% 12u "HTTP Event Collector Token:"
    Pop $Label

    ${NSD_CreateText} 0 13u 100% 12u $HECToken_State
    Pop $HECToken

    ${NSD_CreateLabel} 0 30u 100% 12u "Index Name:"
    Pop $Label

    ${NSD_CreateText} 0 43u 100% 12u $IndexName_State
    Pop $IndexName

    ${NSD_CreateLabel} 0 60u 100% 12u "Indexer:"
    Pop $Label

    ${NSD_CreateText} 0 73u 100% 12u $Indexer_State
    Pop $Indexer

    nsDialogs::Show

  FunctionEnd

  Function pageHubbleConfig_Leave

    ${NSD_GetText} $HECToken $HECToken_State
    ${NSD_GetText} $IndexName $IndexName_State
    ${NSD_GetText} $Indexer $Indexer_State

  FunctionEnd


;--------------------------------
;Custom Finish Page

  Function pageFinish_Show

    # Imports so the checkboxes will show up
    !define SWP_NOSIZE 0x0001
    !define SWP_NOMOVE 0x0002
    !define HWND_TOP 0x0000

    # Create Start Hubble Checkbox
    ${NSD_CreateCheckbox} 120u 90u 100% 12u "&Start Hubble"
    Pop $CheckBox_Hubble_Start
    SetCtlColors $CheckBox_Hubble_Start "" "ffffff"
    # This command required to bring the checkbox to the front
    System::Call "User32::SetWindowPos(i, i, i, i, i, i, i) b ($CheckBox_Hubble_Start, ${HWND_TOP}, 0, 0, 0, 0, ${SWP_NOSIZE}|${SWP_NOMOVE})"

	# Create Start Hubble Delayed Checkbox
	${NSD_CreateCheckbox} 130u 102u 100% 12u "&Delayed Start"
    Pop $CheckBox_Hubble_Start_Delayed
    SetCtlColors $CheckBox_Hubble_Start_Delayed "" "ffffff"
    # This command required to bring the checkbox to the front
    System::Call "User32::SetWindowPos(i, i, i, i, i, i, i) b ($CheckBox_Hubble_Start_Delayed, ${HWND_TOP}, 0, 0, 0, 0, ${SWP_NOSIZE}|${SWP_NOMOVE})"

    # Load current settings for Hubble
    ${If} $StartHubble == 1
        ${NSD_Check} $CheckBox_Hubble_Start
    ${EndIf}

  FunctionEnd


  Function pageFinish_Leave

    # Assign the current checkbox states
    ${NSD_GetState} $CheckBox_Hubble_Start $StartHubble

  FunctionEnd

;--------------------------------
;Installer Sections

  Section -Prerequisites

    ; VCRedist only needed on Windows Server 2008R2/Windows 7 and below
    ${If} ${AtMostWin2008R2}

        !define VC_REDIST_X64_GUID "{5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4}"
        !define VC_REDIST_X86_GUID "{9BE518E6-ECC6-35A9-88E4-87755C07200F}"

        Var /GLOBAL VcRedistGuid
        Var /GLOBAL NeedVcRedist
        ${If} ${CPUARCH} == "AMD64"
            StrCpy $VcRedistGuid ${VC_REDIST_X64_GUID}
        ${Else}
            StrCpy $VcRedistGuid ${VC_REDIST_X86_GUID}
        ${EndIf}

        Push $VcRedistGuid
        Call MsiQueryProductState
        ${If} $NeedVcRedist == "True"
            MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 \
                "VC Redist 2008 SP1 MFC is currently not installed. Would you like to install?" \
                /SD IDYES IDNO endVcRedist

            ClearErrors
            ; The Correct version of VCRedist is copied over by "build_pkg.bat"
            SetOutPath "$INSTDIR\"
            File "vcredist.exe"
            ExecWait "$INSTDIR\vcredist.exe /qb!"
            IfErrors 0 endVcRedist
                MessageBox MB_OK \
                    "VC Redist 2008 SP1 MFC failed to install. Try installing the package manually." \
                    /SD IDOK

            endVcRedist:
        ${EndIf}

    ${EndIf}

  SectionEnd

  Section "MainSection" SEC01

    SetOutPath "$INSTDIR\"
    SetOverwrite ifdiff
	CreateDirectory $INSTDIR\var
    CreateDirectory $INSTDIR\etc\hubble\hubble.d
    File /r "..\..\dist\hubble\"

  SectionEnd

  Section -Post

    WriteUninstaller "$INSTDIR\uninst.exe"

    ; Uninstall Registry Entries
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "DisplayName" "$(^Name)"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "UninstallString" "$INSTDIR\uninst.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "DisplayIcon" "$INSTDIR\hubble.ico"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\services\hubble" \
        "DependOnService" "nsi"

    ; Set the estimated size
    ${GetSize} "$INSTDIR\bin" "/S=OK" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "EstimatedSize" "$0"

    ; Commandline Registry Entries
    WriteRegStr HKLM "${PRODUCT_CALL_REGKEY}" "" "$INSTDIR\hubble.exe"

    ; Register the Hubble Service
    nsExec::Exec "nssm.exe install Hubble $INSTDIR\hubble.exe"
    nsExec::Exec "nssm.exe set Hubble Description Open Source software for security compliance"
    nsExec::Exec "nssm.exe set Hubble Application $INSTDIR\hubble.exe"
    nsExec::Exec "nssm.exe set Hubble AppDirectory $INSTDIR"
    nsExec::Exec "nssm.exe set Hubble AppParameters -c .\etc\hubble\hubble.conf"
    nsExec::Exec "nssm.exe set Hubble Start SERVICE_AUTO_START"

    ExecWait 'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File .\prerequisites.ps1 "$INSTDIR" -FFFeatureOff'
    ExecWait 'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File .\osqueryd_safe_permissions.ps1 "$INSTDIR" -FFFeatureOff'
    ExecWait 'powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File .\hubble_config_permissions.ps1 "$INSTDIR" -FFFeatureOff'
    RMDir /R "$INSTDIR\var\cache" ; removing cache from old version

    ${if} $HECToken_State != "xxxxx-xxx-xxx-xxx-xxxxxx"
	${AndIf} $HECToken_State != ""
        Call makeUserConfig
    ${endif}

    Push "C:\${PFILES}\Hubble"
    Call AddToPath

    Delete "$INSTDIR\vcredist.exe"

  SectionEnd

  Section Uninstall

    Call un.uninstallHubble

    ; Remove C:\Program Files\Hubble from the Path
    Push "C:\${PFILES}\Hubble"
    Call un.RemoveFromPath

  SectionEnd

;--------------------------------
;Uninstaller Section

  Function un.onInit

    ; Load the parameters
    ${GetParameters} $R0

    # Uninstaller: Remove Installation Directory
    ${GetOptions} $R0 "/delete-install-dir" $R1
    IfErrors delete_install_dir_not_found
        StrCpy $DeleteInstallDir 1
    delete_install_dir_not_found:

    MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 \
        "Are you sure you want to completely remove $(^Name) and all of its components?" \
        /SD IDYES IDYES +2
    Abort

  FunctionEnd

  !macro uninstallHubble un
  Function ${un}uninstallHubble

    ; Make sure we're in the right directory
    ${If} $INSTDIR == "c:\salt\bin\Scripts"
      StrCpy $INSTDIR "C:\${PFILES}\Hubble"
    ${EndIf}

    ; Stop and Remove hubble service
    nsExec::Exec 'net stop hubble'
    nsExec::Exec 'sc delete hubble'
    nsExec::Exec 'sc delete hubble_osqueryd'

    ; Remove files
    Delete "$INSTDIR\uninst.exe"
    Delete "$INSTDIR\nssm.exe"
    Delete "$INSTDIR\vcredist.exe"

    ; Remove Registry entries
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY_OTHER}"
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_CALL_REGKEY}"

    ; Automatically close when finished
    SetAutoClose true

    ; Prompt to remove the Installation directory
    ${IfNot} $DeleteInstallDir == 1
        MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 \
            "Would you like to completely remove $INSTDIR and all of its contents?" \
            /SD IDNO IDNO finished
    ${EndIf}

    ; Make sure you're not removing Program Files
    ${If} $INSTDIR != 'Program Files'
    ${AndIf} $INSTDIR != 'Program Files (x86)'
        RMDir /r "$INSTDIR"
    ${EndIf}

    finished:

  FunctionEnd
  !macroend


  !insertmacro uninstallHubble ""
  !insertmacro uninstallHubble "un."


  Function un.onUninstSuccess
    HideWindow
    MessageBox MB_ICONINFORMATION|MB_OK \
        "$(^Name) was successfully removed from your computer." \
        /SD IDOK
  FunctionEnd


;--------------------------------
;functions

  Function .onInit

    Call parseCommandLineSwitches

    ; Check for existing installation
    ReadRegStr $R0 HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "UninstallString"
    StrCmp $R0 "" checkOther
    ; Found existing installation, prompt to uninstall
    MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
        "${PRODUCT_NAME} is already installed.$\n$\n\
        Click `OK` to remove the existing installation." \
        /SD IDOK IDOK uninst
    Abort

    checkOther:
        ; Check for existing installation of hubble
        ReadRegStr $R0 HKLM \
            "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME_OTHER}" \
            "UninstallString"
        StrCmp $R0 "" skipUninstall
        ; Found existing installation, prompt to uninstall
        MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
            "${PRODUCT_NAME_OTHER} is already installed.$\n$\n\
            Click `OK` to remove the existing installation." \
            /SD IDOK IDOK uninst
        Abort

    uninst:

        ; Get current Silent status
        StrCpy $R0 0
        ${If} ${Silent}
            StrCpy $R0 1
        ${EndIf}

        ; Turn on Silent mode
        SetSilent silent

        ; Don't remove all directories
        StrCpy $DeleteInstallDir 0

        ; Uninstall silently
        Call uninstallHubble

        ; Set it back to Normal mode, if that's what it was before
        ${If} $R0 == 0
            SetSilent normal
        ${EndIf}

    skipUninstall:

  FunctionEnd

  Function .onInstSuccess

    ; If StartHubbleDelayed is 1, then set the service to start delayed
    ${If} $StartHubbleDelayed == 1
        nsExec::Exec "nssm.exe set hubble Start SERVICE_DELAYED_AUTO_START"
    ${EndIf}

    ; If start-hubble is 1, then start the service
    ${If} $StartHubble == 1
        nsExec::Exec 'net start hubble'
    ${EndIf}

  FunctionEnd

;--------------------------------
;Helper Functions Section

  Function MsiQueryProductState

    !define INSTALLSTATE_DEFAULT "5"

    Pop $R0
    StrCpy $NeedVcRedist "False"
    System::Call "msi::MsiQueryProductStateA(t '$R0') i.r0"
    StrCmp $0 ${INSTALLSTATE_DEFAULT} +2 0
    StrCpy $NeedVcRedist "True"

  FunctionEnd

;------------------------------------------------------------------------------
; StrStr Function
; - find substring in a string
;
; Usage:
;   Push "this is some string"
;   Push "some"
;   Call StrStr
;   Pop $0 ; "some string"
;------------------------------------------------------------------------------
  !macro StrStr un
  Function ${un}StrStr

    Exch $R1 ; $R1=substring, stack=[old$R1,string,...]
    Exch     ;                stack=[string,old$R1,...]
    Exch $R2 ; $R2=string,    stack=[old$R2,old$R1,...]
    Push $R3 ; $R3=strlen(substring)
    Push $R4 ; $R4=count
    Push $R5 ; $R5=tmp
    StrLen $R3 $R1 ; Get the length of the Search String
    StrCpy $R4 0 ; Set the counter to 0

    loop:
        StrCpy $R5 $R2 $R3 $R4 ; Create a moving window of the string that is
                               ; the size of the length of the search string
        StrCmp $R5 $R1 done    ; Is the contents of the window the same as
                               ; search string, then done
        StrCmp $R5 "" done     ; Is the window empty, then done
        IntOp $R4 $R4 + 1      ; Shift the windows one character
        Goto loop              ; Repeat

    done:
        StrCpy $R1 $R2 "" $R4
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R2
        Exch $R1 ; $R1=old$R1, stack=[result,...]

  FunctionEnd
  !macroend
  !insertmacro StrStr ""
  !insertmacro StrStr "un."


;------------------------------------------------------------------------------
; AddToPath Function
; - Adds item to Path for All Users
; - Overcomes NSIS ReadRegStr limitation of 1024 characters by using Native
;   Windows Commands
;
; Usage:
;   Push "C:\path\to\add"
;   Call AddToPath
;------------------------------------------------------------------------------
  !define Environ 'HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"'
  Function AddToPath

    Exch $0 ; Path to add
    Push $1 ; Current Path
    Push $2 ; Results of StrStr / Length of Path + Path to Add
    Push $3 ; Handle to Reg / Length of Path
    Push $4 ; Result of Registry Call

    ; Open a handle to the key in the registry, handle in $3, Error in $4
    System::Call "advapi32::RegOpenKey(i 0x80000002, t'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', *i.r3) i.r4"
    ; Make sure registry handle opened successfully (returned 0)
    IntCmp $4 0 0 done done

    ; Load the contents of path into $1, Error Code into $4, Path length into $2
    System::Call "advapi32::RegQueryValueEx(i $3, t'PATH', i 0, i 0, t.r1, *i ${NSIS_MAX_STRLEN} r2) i.r4"

    ; Close the handle to the registry ($3)
    System::Call "advapi32::RegCloseKey(i $3)"

    ; Check for Error Code 234, Path too long for the variable
    IntCmp $4 234 0 +4 +4 ; $4 == ERROR_MORE_DATA
        DetailPrint "AddToPath: original length $2 > ${NSIS_MAX_STRLEN}"
        MessageBox MB_OK "PATH not updated, original length $2 > ${NSIS_MAX_STRLEN}"
        Goto done

    ; If no error, continue
    IntCmp $4 0 +5 ; $4 != NO_ERROR
        ; Error 2 means the Key was not found
        IntCmp $4 2 +3 ; $4 != ERROR_FILE_NOT_FOUND
            DetailPrint "AddToPath: unexpected error code $4"
            Goto done
        StrCpy $1 ""

    ; Check if already in PATH
    Push "$1;"          ; The string to search
    Push "$0;"          ; The string to find
    Call StrStr
    Pop $2              ; The result of the search
    StrCmp $2 "" 0 done ; String not found, try again with ';' at the end
                        ; Otherwise, it's already in the path
    Push "$1;"          ; The string to search
    Push "$0\;"         ; The string to find
    Call StrStr
    Pop $2              ; The result
    StrCmp $2 "" 0 done ; String not found, continue (add)
                        ; Otherwise, it's already in the path

    ; Prevent NSIS string overflow
    StrLen $2 $0        ; Length of path to add ($2)
    StrLen $3 $1        ; Length of current path ($3)
    IntOp $2 $2 + $3    ; Length of current path + path to add ($2)
    IntOp $2 $2 + 2     ; Account for the additional ';'
                        ; $2 = strlen(dir) + strlen(PATH) + sizeof(";")

    ; Make sure the new length isn't over the NSIS_MAX_STRLEN
    IntCmp $2 ${NSIS_MAX_STRLEN} +4 +4 0
        DetailPrint "AddToPath: new length $2 > ${NSIS_MAX_STRLEN}"
        MessageBox MB_OK "PATH not updated, new length $2 > ${NSIS_MAX_STRLEN}."
        Goto done

    ; Append dir to PATH
    DetailPrint "Add to PATH: $0"
    StrCpy $2 $1 1 -1       ; Copy the last character of the existing path
    StrCmp $2 ";" 0 +2      ; Check for trailing ';'
        StrCpy $1 $1 -1     ; remove trailing ';'
    StrCmp $1 "" +2         ; Make sure Path is not empty
        StrCpy $0 "$1;$0"   ; Append new path at the end ($0)

    ; We can use the NSIS command here. Only 'ReadRegStr' is affected
    WriteRegExpandStr ${Environ} "PATH" $0

    ; Broadcast registry change to open programs
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

    done:
        Pop $4
        Pop $3
        Pop $2
        Pop $1
        Pop $0

  FunctionEnd


;------------------------------------------------------------------------------
; RemoveFromPath Function
; - Removes item from Path for All Users
; - Overcomes NSIS ReadRegStr limitation of 1024 characters by using Native
;   Windows Commands
;
; Usage:
;   Push "C:\path\to\add"
;   Call RemoveFromPath
;------------------------------------------------------------------------------
  !macro RemoveFromPath un
  Function ${un}RemoveFromPath

    Exch $0
    Push $1
    Push $2
    Push $3
    Push $4
    Push $5
    Push $6

    ; Open a handle to the key in the registry, handle in $3, Error in $4
    System::Call "advapi32::RegOpenKey(i 0x80000002, t'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', *i.r3) i.r4"
    ; Make sure registry handle opened successfully (returned 0)
    IntCmp $4 0 0 done done

    ; Load the contents of path into $1, Error Code into $4, Path length into $2
    System::Call "advapi32::RegQueryValueEx(i $3, t'PATH', i 0, i 0, t.r1, *i ${NSIS_MAX_STRLEN} r2) i.r4"

    ; Close the handle to the registry ($3)
    System::Call "advapi32::RegCloseKey(i $3)"

    ; Check for Error Code 234, Path too long for the variable
    IntCmp $4 234 0 +4 +4 ; $4 == ERROR_MORE_DATA
        DetailPrint "AddToPath: original length $2 > ${NSIS_MAX_STRLEN}"
        MessageBox MB_OK "PATH not updated, original length $2 > ${NSIS_MAX_STRLEN}"
        Goto done

    ; If no error, continue
    IntCmp $4 0 +5 ; $4 != NO_ERROR
        ; Error 2 means the Key was not found
        IntCmp $4 2 +3 ; $4 != ERROR_FILE_NOT_FOUND
            DetailPrint "AddToPath: unexpected error code $4"
            Goto done
        StrCpy $1 ""

    ; Ensure there's a trailing ';'
    StrCpy $5 $1 1 -1   ; Copy the last character of the path
    StrCmp $5 ";" +2    ; Check for trailing ';', if found continue
        StrCpy $1 "$1;" ; ensure trailing ';'

    ; Check for our directory inside the path
    Push $1             ; String to Search
    Push "$0;"          ; Dir to Find
    Call ${un}StrStr
    Pop $2              ; The results of the search
    StrCmp $2 "" done   ; If results are empty, we're done, otherwise continue

    ; Remove our Directory from the Path
    DetailPrint "Remove from PATH: $0"
    StrLen $3 "$0;"       ; Get the length of our dir ($3)
    StrLen $4 $2          ; Get the length of the return from StrStr ($4)
    StrCpy $5 $1 -$4      ; $5 is now the part before the path to remove
    StrCpy $6 $2 "" $3    ; $6 is now the part after the path to remove
    StrCpy $3 "$5$6"      ; Combine $5 and $6

    ; Check for Trailing ';'
    StrCpy $5 $3 1 -1     ; Load the last character of the string
    StrCmp $5 ";" 0 +2    ; Check for ';'
        StrCpy $3 $3 -1     ; remove trailing ';'

    ; Write the new path to the registry
    WriteRegExpandStr ${Environ} "PATH" $3

    ; Broadcast the change to all open applications
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

    done:
        Pop $6
        Pop $5
        Pop $4
        Pop $3
        Pop $2
        Pop $1
        Pop $0

  FunctionEnd
  !macroend
  !insertmacro RemoveFromPath ""
  !insertmacro RemoveFromPath "un."

;--------------------------------
;Specialty Fuctions
  Function makeUserConfig

    confFind:
	IfFileExists "$INSTDIR\etc\hubble\hubble.d\user.conf" confFound confNotFound

    confNotFound:
    ClearErrors
    FileOpen $9 "$INSTDIR\etc\hubble\hubble.d\user.conf" w
    IfErrors confReallyNotFound
        goto confLoop

    confFound:
    Delete "$INSTDIR\etc\hubble\hubble.d\user.conf"
        goto confFind

    confLoop:

        FileWrite $9 "hubblestack:$\r$\n"
        FileWrite $9 "  returner:$\r$\n"
        FileWrite $9 "    splunk:$\r$\n"
        FileWrite $9 "      - token: $HECToken_State$\r$\n"
        FileWrite $9 "        indexer: $Indexer_State$\r$\n"
        FileWrite $9 "        index: $IndexName_State$\r$\n"
        FileWrite $9 "        sourcetype_nova: hubble_audit$\r$\n"
        FileWrite $9 "        sourcetype_nebula: hubble_osquery$\r$\n"
        FileWrite $9 "        sourcetype_osqueryd: hubble_osqd$\r$\n"
        FileWrite $9 "        sourcetype_pulsar: hubble_fim$\r$\n"
        FileWrite $9 "        sourcetype_log: hubble_log$\r$\n"
            goto EndOfFile

    EndOfFile:
    FileClose $9

    confReallyNotFound:

FunctionEnd



Function parseCommandLineSwitches

    ; Load the parameters
    ${GetParameters} $R0

    ; Check for start-hubble switches
    ${GetOptions} $R0 "/start-hubble=" $R2

    # Service: Start Hubble
    ${IfNot} $R2 == ""
        ; If start-hubble was passed something, then set it
        StrCpy $StartHubble $R2
    ${ElseIfNot} $R1 == ""
        ; If start-service was passed something, then set StartHubble to that
        StrCpy $StartHubble $R1
    ${Else}
        ; Otherwise default to 1
        StrCpy $StartHubble 1
    ${EndIf}

    # Service: Hubble Startup Type Delayed
    ${GetOptions} $R0 "/start-hubble-delayed" $R1
    IfErrors start_hubble_delayed_not_found
        StrCpy $StartHubbleDelayed 1
    start_hubble_delayed_not_found:

    # Hubble Config: Token IP/Name
    ${GetOptions} $R0 "/token=" $R1
    ${IfNot} $R1 == ""
        StrCpy $HECToken_State $R1
    ${ElseIf} $HECToken_State == ""
        StrCpy $HECToken_State "xxxxx-xxx-xxx-xxx-xxxxxx"
    ${EndIf}

    # Hubble Config: Index Name
    ${GetOptions} $R0 "/index-name=" $R1
    ${IfNot} $R1 == ""
        StrCpy $IndexName_State $R1
    ${ElseIf} $IndexName_State == ""
        StrCpy $IndexName_State "index"
    ${EndIf}

	# Hubble Config: Indexer
    ${GetOptions} $R0 "/indexer=" $R1
    ${IfNot} $R1 == ""
        StrCpy $Indexer_State $R1
    ${ElseIf} $Indexer_State == ""
        StrCpy $Indexer_State "indexer"
    ${EndIf}

FunctionEnd
