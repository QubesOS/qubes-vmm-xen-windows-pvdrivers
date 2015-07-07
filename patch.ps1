# Patch Xenbus device IDs in xenvbd and xenvif INFs.
# They should bind to the current latest Xenbus PDO revision.
# Xennet binds to xenvif so no changes needed there.
(Get-Content 'xenvbd\src\xenvbd.inf') -replace 'DEV_VBD&REV_00000001', 'DEV_VBD&REV_00000028' | Set-Content 'xenvbd\src\xenvbd.inf'
(Get-Content 'xenvif\src\xenvif.inf') -replace 'DEV_VIF&REV_00000004', 'DEV_VIF&REV_00000028' | Set-Content 'xenvif\src\xenvif.inf'

# Patch evtchn interface headers to only support version 5 to reduce number of PDO revisions and avoid failed assertions.
# Upstream drivers use version 3 so don't change it in xenbus repo (yet).
(Get-Content 'xenbus\include\evtchn_interface.h') -replace '#define XENBUS_EVTCHN_INTERFACE_VERSION_MIN 3', '#define XENBUS_EVTCHN_INTERFACE_VERSION_MIN 5' | Set-Content 'xenbus\include\evtchn_interface.h'
Copy-Item 'xenbus\include\evtchn_interface.h' 'xeniface\include\evtchn_interface.h' -Force
Copy-Item 'xenbus\include\evtchn_interface.h' 'xenvbd\include\evtchn_interface.h' -Force
Copy-Item 'xenbus\include\evtchn_interface.h' 'xenvif\include\evtchn_interface.h' -Force

# Patch xennet.inf to bind to additional xenvif device
$a='%XenNetDesc%		=XenNet_Inst,	XENVIF\VEN_XS0001&DEV_NET&REV_00000002'
$b='%XenNetDesc%		=XenNet_Inst,	XENVIF\VEN_XS0001&DEV_NET&REV_00000002\0'

(Get-Content 'xennet\src\xennet.inf') | Foreach-Object {
    $_.Replace("$a", "$a`n$b")
} | Set-Content 'xennet\src\xennet.inf'
