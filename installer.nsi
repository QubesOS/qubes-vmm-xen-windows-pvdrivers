!include "MUI.nsh"
!include "winver.nsh"

Var MYPROGRAMFILES
Var ARCH_SPEC

!define AppName "Xen PV Drivers"
!define StartMenu "$SMPROGRAMS\${AppName}"
!define Version "0.9.12-pre10"
#!define Version "$%VERSION%"
Name "${AppName}"

#InstallDir "$MYPROGRAMFILES\${AppName}"
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
  File .\doc\xennet.txt
  ExecWait 'NET STOP ShutdownMon'
  StrCmp $ARCH_SPEC "amd64" amd64
  File .\target\winxp\i386\copyconfig.exe
  File .\target\winxp\i386\shutdownmon.exe
  File $%DDK_PATH%\redist\DIFx\DPInst\EngMui\x86\DPInst.exe
  Goto amd64_done
amd64:
  File .\target\winnet\amd64\copyconfig.exe
  File .\target\winnet\amd64\shutdownmon.exe
  File $%DDK_PATH%\redist\DIFx\DPInst\EngMui\amd64\DPInst.exe
amd64_done:
  CreateDirectory "${StartMenu}\"
  CreateShortCut "${StartMenu}\Building.lnk" "$INSTDIR\Building.txt"
  CreateShortCut "${StartMenu}\Installing.lnk" "$INSTDIR\Installing.txt"
  CreateShortCut "${StartMenu}\Readme.lnk" "$INSTDIR\Readme.txt"
  CreateShortCut "${StartMenu}\TODO.lnk" "$INSTDIR\TODO.txt"
  CreateShortCut "${StartMenu}\Wiki Page.lnk" "http://wiki.xensource.com/xenwiki/XenWindowsGplPv" 
  WriteUninstaller $INSTDIR\Uninstall.exe
  CreateShortCut "${StartMenu}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Windows XP" winxp
  SetOutPath $INSTDIR
  File /nonfatal .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winxp\xenpci.inf
  File .\target\winxp\xennet.inf
  File .\target\winxp\xenvbd.inf
  File .\target\winxp\xenscsi.inf
  File .\target\winxp\xenstub.inf
  File /nonfatal .\target\winxp\xengplpv.cat
  SetOutPath $INSTDIR\drivers\i386
  File .\target\winxp\i386\xenpci.sys
  File .\target\winxp\i386\xenhide.sys
  File .\target\winxp\i386\xennet.sys
  File .\target\winxp\i386\xenvbd.sys
  File .\target\winxp\i386\xenscsi.sys
  File .\target\winxp\i386\xenstub.sys
SectionEnd

Section "Windows 2003 x32" win2k3x32
  SetOutPath $INSTDIR
  File /nonfatal .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winnet\xenpci.inf
  File .\target\winnet\xennet.inf
  File .\target\winnet\xenvbd.inf
  File .\target\winnet\xenscsi.inf
  File .\target\winnet\xenstub.inf
  File /nonfatal .\target\winnet\xengplpv.cat
  SetOutPath $INSTDIR\drivers\i386
  File .\target\winnet\i386\xenpci.sys
  File .\target\winnet\i386\xenhide.sys
  File .\target\winnet\i386\xennet.sys
  File .\target\winnet\i386\xenvbd.sys
  File .\target\winnet\i386\xenscsi.sys
  File .\target\winnet\i386\xenstub.sys
SectionEnd

Section "Windows 2003 x64" win2k3x64
  SetOutPath $INSTDIR
  File /nonfatal .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winnet\xenpci.inf
  File .\target\winnet\xennet.inf
  File .\target\winnet\xenvbd.inf
  File .\target\winnet\xenscsi.inf
  File .\target\winnet\xenstub.inf
  File /nonfatal .\target\winnet\xengplpv.cat
  SetOutPath $INSTDIR\drivers\amd64
  File .\target\winnet\amd64\xenpci.sys
  File .\target\winnet\amd64\xenhide.sys
  File .\target\winnet\amd64\xennet.sys
  File .\target\winnet\amd64\xenvbd.sys
  File .\target\winnet\amd64\xenscsi.sys
  File .\target\winnet\amd64\xenstub.sys
SectionEnd

Section "Windows 2008 x32" win2k8x32
  SetOutPath $INSTDIR
  File /nonfatal .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winlh\xenpci.inf
  File .\target\winlh\xennet.inf
  File .\target\winlh\xenvbd.inf
  File .\target\winlh\xenscsi.inf
  File .\target\winlh\xenstub.inf
  File /nonfatal .\target\winlh\xengplpv.cat
  SetOutPath $INSTDIR\drivers\i386
  File .\target\winlh\i386\xenpci.sys
  File .\target\winlh\i386\xenhide.sys
  File .\target\winlh\i386\xennet.sys
  File .\target\winlh\i386\xenvbd.sys
  File .\target\winlh\i386\xenscsi.sys
  File .\target\winlh\i386\xenstub.sys
SectionEnd

Section "Windows 2008 x64" win2k8x64
  SetOutPath $INSTDIR
  File /nonfatal .\ca.cer
  SetOutPath $INSTDIR\drivers
  File .\target\winlh\xenpci.inf
  File .\target\winlh\xennet.inf
  File .\target\winlh\xenvbd.inf
  File .\target\winlh\xenscsi.inf
  File .\target\winlh\xenstub.inf
  File /nonfatal .\target\winlh\xengplpv.cat
  SetOutPath $INSTDIR\drivers\amd64
  File .\target\winlh\amd64\xenpci.sys
  File .\target\winlh\amd64\xenhide.sys
  File .\target\winlh\amd64\xennet.sys
  File .\target\winlh\amd64\xenvbd.sys
  File .\target\winlh\amd64\xenscsi.sys
  File .\target\winlh\amd64\xenstub.sys
SectionEnd

Section /o "Install Cert" installcert
  # For some reason this next line doesn't need any double quotes around
  # the filename, and in fact it breaks when they are included...
  ExecWait 'rundll32.exe cryptext.dll,CryptExtAddCER $INSTDIR\ca.cer'
SectionEnd

Section "Install Drivers" installdrivers
  ExecWait '"$INSTDIR\DPInst.exe" /PATH "$INSTDIR\drivers" /LM /SA /SE /SW'
!if false
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

  Push "$INSTDIR\drivers"
  Push "$INSTDIR\drivers\xenpci.inf"
  Push "PCI\VEN_5853&DEV_0001"
  Call InstallUpgradeDriver
!endif
SectionEnd

Section "Shutdown Monitor Service" shutdownmon
  ExecWait '"$INSTDIR\ShutdownMon.exe" -o'
  ExecWait '"$INSTDIR\ShutdownMon.exe" -u'
  ExecWait '"$INSTDIR\ShutdownMon.exe" -i'
  ExecWait 'NET START ShutdownMon'
SectionEnd
  
Section /o "Copy Network Config" copynetworkconfig
  MessageBox MB_OKCANCEL "This will copy the network IP configuration from the qemu network adapter to the gplpv xennet network adapter. Ensure that all the drivers are loaded for all the network adapters before clicking OK" IDCANCEL done
  ExecWait '"$INSTDIR\copyconfig.exe"'
done:
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

  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" PROCESSOR_ARCHITECTURE
  StrCmp $0 "AMD64" is_amd64
  StrCpy $MYPROGRAMFILES $PROGRAMFILES
  StrCpy $ARCH_SPEC "i386"
  Goto amd64_done
is_amd64:
  StrCpy $MYPROGRAMFILES $PROGRAMFILES64
  StrCpy $ARCH_SPEC "amd64"
amd64_done:
  StrCpy $INSTDIR "$MYPROGRAMFILES\${AppName}"
  
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
  
  StrCpy $newarch $arch
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

  StrCmp $arch "winxp" set_winxp
  SectionGetFlags ${winxp} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${winxp} $0
  goto check_2k3x32
set_winxp:
  SectionGetFlags ${winxp} $0
  IntOp $0 $0 | ${SF_SELECTED}
  SectionSetFlags ${winxp} $0  
check_2k3x32:
  StrCmp $arch "win2k3x32" set_2k3x32
  SectionGetFlags ${win2k3x32} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k3x32} $0
  goto check_2k3x64
set_2k3x32:
  SectionGetFlags ${win2k3x32} $0
  IntOp $0 $0 | ${SF_SELECTED}
  SectionSetFlags ${win2k3x32} $0  
check_2k3x64:
  StrCmp $arch "win2k3x64" set_2k3x64
  SectionGetFlags ${win2k3x64} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k3x64} $0
  goto check_2k8x32
set_2k3x64:
  SectionGetFlags ${win2k3x64} $0
  IntOp $0 $0 | ${SF_SELECTED}
  SectionSetFlags ${win2k3x64} $0  
check_2k8x32:
  StrCmp $arch "win2k8x32" set_2k8x32
  SectionGetFlags ${win2k8x32} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k8x32} $0
  goto check_2k8x64
set_2k8x32:
  SectionGetFlags ${win2k8x32} $0
  IntOp $0 $0 | ${SF_SELECTED}
  SectionSetFlags ${win2k8x32} $0  
check_2k8x64:
  StrCmp $arch "win2k8x64" set_2k8x64
  SectionGetFlags ${win2k8x64} $0
  IntOp $0 $0 & ${SECTION_OFF}
  SectionSetFlags ${win2k8x64} $0
  goto done
set_2k8x64:
  SectionGetFlags ${win2k8x64} $0
  IntOp $0 $0 | ${SF_SELECTED}
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
