!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef BIN_DIR
  !define BIN_DIR "."
!endif
!ifndef LICENSE_FILE
  !define LICENSE_FILE "LICENSE"
!endif
!ifndef OUTPUT_FILE
  !define OUTPUT_FILE "shekyl-setup.exe"
!endif

Name "Shekyl ${VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\Shekyl"
InstallDirRegKey HKLM "Software\Shekyl" "InstallDir"
RequestExecutionLevel admin

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

Section "Shekyl Core (required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"

  File "${BIN_DIR}\shekyld.exe"
  File /nonfatal "${BIN_DIR}\shekyl-wallet-cli.exe"
  File /nonfatal "${BIN_DIR}\shekyl-wallet-rpc.exe"
  File /nonfatal "${BIN_DIR}\shekyl-gen-trusted-multisig.exe"

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

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Add to PATH" SecPath
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  StrCpy $0 "$0;$INSTDIR"
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"
SectionEnd

Section "Start Menu Shortcuts" SecShortcuts
  CreateDirectory "$SMPROGRAMS\Shekyl"
  CreateShortCut "$SMPROGRAMS\Shekyl\Shekyl Daemon.lnk" "$INSTDIR\shekyld.exe"
  CreateShortCut "$SMPROGRAMS\Shekyl\Shekyl Wallet CLI.lnk" "$INSTDIR\shekyl-wallet-cli.exe"
  CreateShortCut "$SMPROGRAMS\Shekyl\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Shekyl daemon and wallet binaries."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Add Shekyl installation directory to the system PATH."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Create Start Menu shortcuts."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  Delete "$INSTDIR\shekyld.exe"
  Delete "$INSTDIR\shekyl-wallet-cli.exe"
  Delete "$INSTDIR\shekyl-wallet-rpc.exe"
  Delete "$INSTDIR\shekyl-gen-trusted-multisig.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\Shekyl\Shekyl Daemon.lnk"
  Delete "$SMPROGRAMS\Shekyl\Shekyl Wallet CLI.lnk"
  Delete "$SMPROGRAMS\Shekyl\Uninstall.lnk"
  RMDir "$SMPROGRAMS\Shekyl"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Shekyl"
  DeleteRegKey HKLM "Software\Shekyl"
SectionEnd
