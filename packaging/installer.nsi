Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!ifndef APP_VERSION
  !error "APP_VERSION is required"
!endif
Name "Xdecrypt Rust ${APP_VERSION}"
OutFile "${PROJECT_ROOT}\dist\Xdecrypt-Rust-${APP_VERSION}-windows-x64-setup.exe"
InstallDir "$LOCALAPPDATA\Programs\Xdecrypt Rust"
InstallDirRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma
VIProductVersion "${APP_VERSION}.0"
VIAddVersionKey "ProductName" "Xdecrypt Rust"
VIAddVersionKey "FileDescription" "Xdecrypt Rust Windows x64 安装程序"
VIAddVersionKey "FileVersion" "${APP_VERSION}"
VIAddVersionKey "LegalCopyright" "2026"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "此安装包需要 Windows x64。"
    Abort
  ${EndIf}
FunctionEnd

Section "应用"
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File "${PROJECT_ROOT}\target\release\xdecrypt-rust.exe"
  File "${PROJECT_ROOT}\README.md"
  File "${PROJECT_ROOT}\THIRD_PARTY_NOTICES.txt"
  CreateDirectory "$SMPROGRAMS\Xdecrypt Rust"
  CreateShortcut "$SMPROGRAMS\Xdecrypt Rust\Xdecrypt Rust.lnk" "$INSTDIR\xdecrypt-rust.exe"
  CreateShortcut "$SMPROGRAMS\Xdecrypt Rust\卸载.lnk" "$INSTDIR\Uninstall.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "DisplayName" "Xdecrypt Rust"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "DisplayIcon" "$INSTDIR\xdecrypt-rust.exe"
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  Delete "$INSTDIR\xdecrypt-rust.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\THIRD_PARTY_NOTICES.txt"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$SMPROGRAMS\Xdecrypt Rust\Xdecrypt Rust.lnk"
  Delete "$SMPROGRAMS\Xdecrypt Rust\卸载.lnk"
  RMDir "$SMPROGRAMS\Xdecrypt Rust"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\XdecryptRust"
SectionEnd
