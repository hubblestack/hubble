;HubbleStack Installer
;Install Hubble with options
;Written by Chad Mills

;--------------------------------
!define PRODUCT_NAME "Hubble"
!define PRODUCT_NAME_OTHER "HubbleStack"
!define PRODUCT_PUBLISHER "Adobe, Inc"
!define PRODUCT_WEB_SITE "https://hubblestack.io/"
!define PRODUCT_CALL_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\salt-call.exe"
!define PRODUCT_CP_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\salt-cp.exe"
!define PRODUCT_KEY_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\salt-key.exe"
!define PRODUCT_MASTER_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\salt-master.exe"
!define PRODUCT_MINION_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\salt-minion.exe"
!define PRODUCT_RUN_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\salt-run.exe"
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
${StrLoc}
${StrStrAdv}

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

; Part of the Trim function for Strings
!define Trim "!insertmacro Trim"
!macro Trim ResultVar String
    Push "${String}"
    Call Trim
    Pop "${ResultVar}"
!macroend


;--------------------------------
;General
  ;Name and File
  Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
  OutFile "Hubble-${PRODUCT_VERSION}-${CPUARCH}-Setup.exe"
  
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
  !define MUI_WELCOMEFINISHPAGE_BITMAP "panel.bmp"


;--------------------------------
;Pages

  ; Welcome page
  !insertmacro MUI_PAGE_WELCOME

  ; License page
  !insertmacro MUI_PAGE_LICENSE "LICENSE.txt"

  ; Configure Minion page
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
  Var CheckBox_Hubble
  Var HECToken
  Var HECToken_State
  Var IndexName
  Var IndexName_State
  Var StartHubble


;--------------------------------
;Hubble Settings Dialog Box

  Function pageHubbleConfig

    # Set Page Title and Description
    !insertmacro MUI_HEADER_TEXT "Hubble Settings" "Set the Token and Index for Splunk"
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

    nsDialogs::Show

  FunctionEnd
  
  Function pageMinionConfig_Leave

    ${NSD_GetText} $HECToken $HECToken_State
    ${NSD_GetText} $IndexName $IndexName_State

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
    Pop $CheckBox_Hubble
    SetCtlColors $CheckBox_Hubble "" "ffffff"
    # This command required to bring the checkbox to the front
    System::Call "User32::SetWindowPos(i, i, i, i, i, i, i) b ($CheckBox_Hubble, ${HWND_TOP}, 0, 0, 0, 0, ${SWP_NOSIZE}|${SWP_NOMOVE})"

    # Load current settings for Hubble
    ${If} $StartHubble == 1
        ${NSD_Check} $CheckBox_Hubble
    ${EndIf}

  FunctionEnd


  Function pageFinish_Leave

    # Assign the current checkbox states
    ${NSD_GetState} $CheckBox_Hubble $StartHubble

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
            File "..\prereqs\vcredist.exe"
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
    SetOverwrite off
    File /r "..\..\dist\hubble\"

  SectionEnd

;--------------------------------
;functions

Function .onInit

    Call getMinionConfig

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
        ; Check for existing installation of full salt
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
        Call uninstallSalt

        ; Set it back to Normal mode, if that's what it was before
        ${If} $R0 == 0
            SetSilent normal
        ${EndIf}

    skipUninstall:

FunctionEnd

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  ;ADD YOUR OWN FILES HERE...

  Delete "$INSTDIR\Uninstall.exe"

  RMDir "$INSTDIR"

  DeleteRegKey /ifempty HKCU "Software\Modern UI Test"

SectionEnd