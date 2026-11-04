; The Windows installer. Built as `.github/workflows/gitian.yml` does:
;
;   makensis -DVERSION=<version> -DBIN_DIR=<dir holding shekyld.exe> \
;            -DLICENSE_FILE=<path>/LICENSE -DOUTPUT_FILE=<path>/shekyl-setup.exe \
;            contrib/packaging/windows/shekyl.nsi
;
; makensis resolves a relative path against this script's directory, not
; the working directory, so the defaults below are spelled from here: the
; repository's LICENSE is three directories up (DC-F37).
!include "MUI2.nsh"
!include "StrFunc.nsh"
!include "x64.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef BIN_DIR
  !define BIN_DIR "."
!endif
!ifndef LICENSE_FILE
  !define LICENSE_FILE "..\..\..\LICENSE"
!endif
!ifndef OUTPUT_FILE
  !define OUTPUT_FILE "shekyl-setup.exe"
!endif

Name "Shekyl ${VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\Shekyl"
RequestExecutionLevel admin

; Shekyl is 64-bit only, and the installer itself is a 32-bit program: on
; 64-bit Windows its HKLM writes are redirected into the 32-bit view
; (`SOFTWARE\WOW6432Node\...`) unless it selects the 64-bit view, which
; is where Windows Error Reporting reads `ExcludedApplications` for a
; 64-bit `shekyld.exe` and where the uninstaller must find the keys again
; (DC-F36). `SetRegView` does not reach `InstallDirRegKey`, so the install
; directory is read here instead. A 32-bit Windows cannot run the daemon
; and is refused.
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "Shekyl is 64-bit only; this Windows is 32-bit."
    Abort
  ${EndIf}
  SetRegView 64
  ReadRegStr $0 HKLM "Software\Shekyl" "InstallDir"
  StrCmp $0 "" +2
    StrCpy $INSTDIR $0
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_LICENSE "${LICENSE_FILE}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

${StrStr}
${UnStrStr}
${UnStrRep}

Section "Shekyl Core (required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"

  File "${BIN_DIR}\shekyld.exe"
  File /nonfatal "${BIN_DIR}\shekyl-cli.exe"
  File /nonfatal "${BIN_DIR}\shekyl-wallet-rpc.exe"

  WriteRegStr HKLM "Software\Shekyl" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "DisplayName" "Shekyl ${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "Publisher" "Shekyl Foundation"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "URLInfoAbout" "https://shekyl.org"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl" \
    "NoRepair" 1

  ; Windows Error Reporting reports a faulting process and offers to send
  ; its memory. The daemon forbids its own dumps from inside
  ; (DAEMON_CONFIG_CUTOVER.md DC-Q21, DC-F38): its top-level exception
  ; filter and its panic hook end the process before WER's fault path
  ; runs. What they cannot reach is a fail-fast the process does not
  ; route (an allocation failure's abort, OS-heap corruption, a C++ /GS
  ; check). For those this value, the one WerAddExcludedApplication
  ; writes, is the backstop: it excludes the name from WER's *reporting*,
  ; so no report leaves the machine. It does not stop a machine-wide
  ; LocalDumps policy (`...\Windows Error Reporting\LocalDumps`) writing a
  ; dump of those cases; the operator guide says so. WER is a per-machine
  ; setting, so it is written here, where the installer already holds the
  ; machine, in the 64-bit view (.onInit).
  WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications" \
    "shekyld.exe" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Add to PATH" SecPath
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${StrStr} $1 $0 $INSTDIR
  StrCmp $1 "" 0 PathAlreadyPresent
    StrCpy $0 "$0;$INSTDIR"
    WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"
  PathAlreadyPresent:
SectionEnd

Section "Start Menu Shortcuts" SecShortcuts
  CreateDirectory "$SMPROGRAMS\Shekyl"
  CreateShortCut "$SMPROGRAMS\Shekyl\Shekyl Daemon.lnk" "$INSTDIR\shekyld.exe"
  CreateShortCut "$SMPROGRAMS\Shekyl\Shekyl CLI Wallet.lnk" "$INSTDIR\shekyl-cli.exe"
  CreateShortCut "$SMPROGRAMS\Shekyl\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Shekyl daemon and wallet binaries."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Add Shekyl installation directory to the system PATH."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Create Start Menu shortcuts."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  Delete "$INSTDIR\shekyld.exe"
  Delete "$INSTDIR\shekyl-cli.exe"
  Delete "$INSTDIR\shekyl-wallet-rpc.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\Shekyl\Shekyl Daemon.lnk"
  Delete "$SMPROGRAMS\Shekyl\Shekyl Wallet CLI.lnk"
  Delete "$SMPROGRAMS\Shekyl\Uninstall.lnk"
  RMDir "$SMPROGRAMS\Shekyl"

  ; Remove $INSTDIR from system PATH (handles ";dir", "dir;", and lone "dir")
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${UnStrStr} $1 $0 $INSTDIR
  StrCmp $1 "" PathCleanDone
    ${UnStrRep} $0 $0 ";$INSTDIR" ""
    ${UnStrRep} $0 $0 "$INSTDIR;" ""
    ${UnStrRep} $0 $0 "$INSTDIR" ""
    WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"
  PathCleanDone:

  DeleteRegValue HKLM "SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications" "shekyld.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl"
  DeleteRegKey HKLM "Software\Shekyl"
SectionEnd
