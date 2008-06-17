!include "MUI.nsh"
!include "driver.nsh"

!define AppName "Xen PV Drivers"
!define StartMenu "$SMPROGRAMS\${AppName}"
!define Version "0.9.10-pre3"
#!define Version "$%VERSION%"
Name "${AppName}"
InstallDir "$PROGRAMFILES\${AppName}"
OutFile "${AppName} ${Version}.exe"

# make sure /GPLPV is not currently active

#!define MUI_PAGE_CUSTOMFUNCTION_PRE WelcomePageSetupLinkPre
#!define MUI_PAGE_CUSTOMFUNCTION_SHOW WelcomePageSetupLinkShow
!define MUI_STARTMENUPAGE
!define MUI_COMPONENTSPAGE
!define MUI_DIRECTORYPAGE
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!define MUI_UNINSTALLER
!insertmacro MUI_LANGUAGE "English"

Section "Common Files"
  SectionIn RO
  SetOutPath $INSTDIR
  File .\doc\Building.txt
  File .\doc\Installing.txt
  File .\doc\Readme.txt
  File .\doc\TODO.txt
  CreateDirectory "${StartMenu}\"
  CreateShortCut "${StartMenu}\Building.lnk" "$INSTDIR\Building.txt"
  CreateShortCut "${StartMenu}\Installing.lnk" "$INSTDIR\Installing.txt"
  CreateShortCut "${StartMenu}\Readme.lnk" "$INSTDIR\Readme.txt"
  CreateShortCut "${StartMenu}\TODO.lnk" "$INSTDIR\TODO.txt"
  CreateShortCut "${StartMenu}\Wiki Page.lnk" "http://wiki.xensource.com/xenwiki/XenWindowsGplPv" 
  WriteUninstaller $INSTDIR\Uninstall.exe
  CreateShortCut "${StartMenu}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

SectionEnd

Section "Shutdown Monitor Service" shutdownmon
  SetOutPath $INSTDIR

  ExecWait 'NET STOP XenShutdownMon'
  File .\target\ShutdownMon.exe
#  CreateShortCut "${StartMenu}\Install Shutdown Service.lnk" "$INSTDIR\ShutdownMon.exe" "-i"
#  CreateShortCut "${StartMenu}\UnInstall Shutdown Service.lnk" "$INSTDIR\ShutdownMon.exe" "-u"
  ExecWait '"$INSTDIR\ShutdownMon.exe" -i'
  ExecWait 'NET START XenShutdownMon'
SectionEnd
  
Section "Windows 2000" win2k
  SetOutPath $INSTDIR
  File /r .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\win2k\xenpci.inf
  File .\target\win2k\xennet.inf
  File .\target\win2k\xenvbd.inf
  File .\target\win2k\xenscsi.inf
  File .\target\win2k\xenstub.inf
  SetOutPath $INSTDIR\drivers\i386
  File .\target\win2k\i386\xenpci.sys
  File .\target\win2k\i386\xenhide.sys
  File .\target\win2k\i386\xennet.sys
  File .\target\win2k\i386\xenvbd.sys
  File .\target\win2k\i386\xenscsi.sys
  File .\target\win2k\i386\xenstub.sys
  File .\target\win2k\i386\xenconfig.sys
SectionEnd

Section "Windows XP" winxp
  SetOutPath $INSTDIR
  File /r .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winxp\xenpci.inf
  File .\target\winxp\xennet.inf
  File .\target\winxp\xenvbd.inf
  File .\target\winxp\xenscsi.inf
  File .\target\winxp\xenstub.inf
  File .\target\winxp\xengplpv.cat
  SetOutPath $INSTDIR\drivers\i386
  File .\target\winxp\i386\xenpci.sys
  File .\target\winxp\i386\xenhide.sys
  File .\target\winxp\i386\xennet.sys
  File .\target\winxp\i386\xenvbd.sys
  File .\target\winxp\i386\xenscsi.sys
  File .\target\winxp\i386\xenstub.sys
  File .\target\winxp\i386\xenconfig.sys
SectionEnd

Section "Windows 2003 x32" win2k3x32
  SetOutPath $INSTDIR
  File /r .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winnet\xenpci.inf
  File .\target\winnet\xennet.inf
  File .\target\winnet\xenvbd.inf
  File .\target\winnet\xenscsi.inf
  File .\target\winnet\xenstub.inf
  File .\target\winnet\xengplpv.cat
  SetOutPath $INSTDIR\drivers\i386
  File .\target\winnet\i386\xenpci.sys
  File .\target\winnet\i386\xenhide.sys
  File .\target\winnet\i386\xennet.sys
  File .\target\winnet\i386\xenvbd.sys
  File .\target\winnet\i386\xenscsi.sys
  File .\target\winnet\i386\xenstub.sys
  File .\target\winnet\i386\xenconfig.sys
SectionEnd

Section "Windows 2003 x64" win2k3x64
  SetOutPath $INSTDIR
  File /r .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winnet\xenpci.inf
  File .\target\winnet\xennet.inf
  File .\target\winnet\xenvbd.inf
  File .\target\winnet\xenscsi.inf
  File .\target\winnet\xenstub.inf
  File .\target\winnet\xengplpv.cat
  SetOutPath $INSTDIR\drivers\amd64
  File .\target\winnet\amd64\xenpci.sys
  File .\target\winnet\amd64\xenhide.sys
  File .\target\winnet\amd64\xennet.sys
  File .\target\winnet\amd64\xenvbd.sys
  File .\target\winnet\amd64\xenscsi.sys
  File .\target\winnet\amd64\xenstub.sys
  File .\target\winnet\amd64\xenconfig.sys
SectionEnd

Section "Windows 2008 x32" win2k8x32
  SetOutPath $INSTDIR
  File /r .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winlh\xenpci.inf
  File .\target\winlh\xennet.inf
  File .\target\winlh\xenvbd.inf
  File .\target\winlh\xenscsi.inf
  File .\target\winlh\xenstub.inf
  File .\target\winlh\xengplpv.cat
  SetOutPath $INSTDIR\drivers\i386
  File .\target\winlh\i386\xenpci.sys
  File .\target\winlh\i386\xenhide.sys
  File .\target\winlh\i386\xennet.sys
  File .\target\winlh\i386\xenvbd.sys
  File .\target\winlh\i386\xenscsi.sys
  File .\target\winlh\i386\xenstub.sys
  File .\target\winlh\i386\xenconfig.sys
SectionEnd

Section "Windows 2008 x64" win2k8x64
  SetOutPath $INSTDIR
  File /r .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winlh\xenpci.inf
  File .\target\winlh\xennet.inf
  File .\target\winlh\xenvbd.inf
  File .\target\winlh\xenscsi.inf
  File .\target\winlh\xenstub.inf
  File .\target\winlh\xengplpv.cat
  SetOutPath $INSTDIR\drivers\amd64
  File .\target\winlh\amd64\xenpci.sys
  File .\target\winlh\amd64\xenhide.sys
  File .\target\winlh\amd64\xennet.sys
  File .\target\winlh\amd64\xenvbd.sys
  File .\target\winlh\amd64\xenscsi.sys
  File .\target\winlh\amd64\xenstub.sys
  File .\target\winlh\amd64\xenconfig.sys
SectionEnd

Section /o "Install Cert" installcert
  ExecWait 'rundll32.exe cryptext.dll,CryptExtAddCER $INSTDIR\ca.cer'
SectionEnd

Section "Install Drivers" installdrivers
  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenpci.inf"
  Push "PCI\VEN_5853&DEV_0001"
  Call InstallUpgradeDriver

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xennet.inf"
  Push "XEN\VIF"
  Call InstallUpgradeDriver

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenvbd.inf"
  Push "XEN\VBD"
  Call InstallUpgradeDriver

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenscsi.inf"
  Push "XEN\VSCSI"
  Call InstallUpgradeDriver

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenstub.inf"
  Push "XEN\CONSOLE"
  Call InstallUpgradeDriver

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenstub.inf"
  Push "XEN\VFB"
  Call InstallUpgradeDriver

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenstub.inf"
  Push "XEN\VKBD"
  Call InstallUpgradeDriver
SectionEnd

Var arch

Function .onInit
  Push $0
 
  ReadRegStr $0 HKLM SYSTEM\CurrentControlSet\Control SystemStartOptions
  Push $0
  Push "GPLPV"
  Call StrContains
  Pop $0
  StrCmp $0 "" no_GPLPV

  ReadRegStr $0 HKLM SYSTEM\CurrentControlSet\Services\XenHide DisplayName
  StrCmp $0 "" 0 no_GPLPV

  MessageBox MB_OK "Warning - GPLPV specified on boot but drivers not installed yet. You should cancel now and boot without GPLPV"
no_GPLPV:
  
  Call GetWindowsVersion
  Pop $R0
  
  StrCmp $R0 "2000" 0 check_XP
  StrCpy $arch "win2k"
  Goto version_done
check_XP:
  StrCmp $R0 "XP" 0 check_2k3
  StrCpy $arch "winxp"
  Goto version_done
check_2k3:
  StrCmp $R0 "2003" 0 check_2k8
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" PROCESSOR_ARCHITECTURE
  StrCmp $0 "AMD64" version_2k3x64
  StrCpy $arch "win2k3x32"
  Goto version_done
version_2k3x64:
  StrCpy $arch "win2k3x64"
  Goto version_done
check_2k8:
  StrCmp $R0 "Vista" 0 version_error
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" PROCESSOR_ARCHITECTURE
  StrCmp $0 "AMD64" version_2k8x64
  StrCpy $arch "win2k8x32"
  Goto version_done
version_2k8x64:
  StrCpy $arch "win2k8x64"
  Goto version_done
version_error:
  MessageBox MB_OK "Unable to detect windows version - proceed with caution"
  StrCpy $arch ""

version_done:
  Call SelectSection

#  SectionGetFlags ${sec1} $0
#  IntOp $0 $0 | ${SF_SELECTED}
#  SectionSetFlags ${sec1} $0
 
  Pop $0
FunctionEnd

Var NewArch

Function .onSelChange
  Push $0
  
  StrCmp $arch "win2k" check_xp
  SectionGetFlags ${win2k} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 ${SF_SELECTED} 0 check_xp check_xp
  StrCpy $newarch "win2k"
check_xp:
  StrCmp $arch "winxp" check_2k3x32
  SectionGetFlags ${winxp} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 ${SF_SELECTED} 0 check_2k3x32 check_2k3x32
  StrCpy $newarch "winxp"
check_2k3x32:
  StrCmp $arch "win2k3x32" check_2k3x64
  SectionGetFlags ${win2k3x32} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 ${SF_SELECTED} 0 check_2k3x64 check_2k3x64
  StrCpy $newarch "win2k3x32"
check_2k3x64:
  StrCmp $arch "win2k3x64" check_2k8x32
  SectionGetFlags ${win2k3x64} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 ${SF_SELECTED} 0 check_2k8x32 check_2k8x32
  StrCpy $newarch "win2k3x64"
check_2k8x32:
  StrCmp $arch "win2k8x32" check_2k8x64
  SectionGetFlags ${win2k8x32} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 ${SF_SELECTED} 0 check_2k8x64 check_2k8x64
  StrCpy $newarch "win2k8x32"
check_2k8x64:
  StrCmp $arch "win2k8x64" done
  SectionGetFlags ${win2k8x64} $0
  IntOp $0 $0 & ${SF_SELECTED}
  IntCmp $0 ${SF_SELECTED} 0 done done
  StrCpy $newarch "win2k8x64"
done:
  StrCpy $arch $newarch
  Call SelectSection

  Pop $0
FunctionEnd

Function SelectSection
  Push $0

  StrCmp $arch "win2k" check_xp
  SectionGetFlags ${win2k} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k} $0
check_xp:
  StrCmp $arch "winxp" check_2k3x32
  SectionGetFlags ${winxp} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${winxp} $0
check_2k3x32:
  StrCmp $arch "win2k3x32" check_2k3x64
  SectionGetFlags ${win2k3x32} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k3x32} $0
check_2k3x64:
  StrCmp $arch "win2k3x64" check_2k8x32
  SectionGetFlags ${win2k3x64} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k3x64} $0
check_2k8x32:
  StrCmp $arch "win2k8x32" check_2k8x64
  SectionGetFlags ${win2k8x32} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k8x32} $0
check_2k8x64:
  StrCmp $arch "win2k8x64" done
  SectionGetFlags ${win2k8x64} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k8x64} $0
done:
  Pop $0

FunctionEnd

Section "Uninstall"
  Delete "${StartMenu}\Uninstall.lnk"
  RMDir "${StartMenu}\"
  Delete $INSTDIR\uninstall.exe
  RMDir $INSTDIR
SectionEnd

Var STR_HAYSTACK
Var STR_NEEDLE
Var STR_CONTAINS_VAR_1
Var STR_CONTAINS_VAR_2
Var STR_CONTAINS_VAR_3
Var STR_CONTAINS_VAR_4
Var STR_RETURN_VAR
 
Function StrContains
  Exch $STR_NEEDLE
  Exch 1
  Exch $STR_HAYSTACK
  ; Uncomment to debug
  ;MessageBox MB_OK 'STR_NEEDLE = $STR_NEEDLE STR_HAYSTACK = $STR_HAYSTACK '
    StrCpy $STR_RETURN_VAR ""
    StrCpy $STR_CONTAINS_VAR_1 -1
    StrLen $STR_CONTAINS_VAR_2 $STR_NEEDLE
    StrLen $STR_CONTAINS_VAR_4 $STR_HAYSTACK
    loop:
      IntOp $STR_CONTAINS_VAR_1 $STR_CONTAINS_VAR_1 + 1
      StrCpy $STR_CONTAINS_VAR_3 $STR_HAYSTACK $STR_CONTAINS_VAR_2 $STR_CONTAINS_VAR_1
      StrCmp $STR_CONTAINS_VAR_3 $STR_NEEDLE found
      StrCmp $STR_CONTAINS_VAR_1 $STR_CONTAINS_VAR_4 done
      Goto loop
    found:
      StrCpy $STR_RETURN_VAR $STR_NEEDLE
      Goto done
    done:
   Pop $STR_NEEDLE ;Prevent "invalid opcode" errors and keep the
   Exch $STR_RETURN_VAR  
FunctionEnd
