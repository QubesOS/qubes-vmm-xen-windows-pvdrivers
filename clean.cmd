@echo off

rd /s /q %~dp0\.artifacts
rd /s /q %~dp0\vs2022\tmp
rd /s /q %~dp0\vs2022\x64
del /s /q /f %~dp0\sign.crt
del /s /q /f %~dp0\include\qwt_version.h

rd /s /q %~dp0\xenbus\xenbus
rd /s /q %~dp0\xenbus\vs2022\Windows10Debug
rd /s /q %~dp0\xenbus\vs2022\Windows10Release
rd /s /q %~dp0\xenbus\vs2022\x64
rd /s /q %~dp0\xenbus\vs2022\package\Windows10Debug
rd /s /q %~dp0\xenbus\vs2022\package\Windows10Release
rd /s /q %~dp0\xenbus\vs2022\xen\Windows10Debug
rd /s /q %~dp0\xenbus\vs2022\xen\Windows10Release
rd /s /q %~dp0\xenbus\vs2022\xen\x64
rd /s /q %~dp0\xenbus\vs2022\xenbus\Windows10Debug
rd /s /q %~dp0\xenbus\vs2022\xenbus\Windows10Release
rd /s /q %~dp0\xenbus\vs2022\xenbus_monitor\x64
rd /s /q %~dp0\xenbus\vs2022\xenfilt\Windows10Debug
rd /s /q %~dp0\xenbus\vs2022\xenfilt\Windows10Release

rd /s /q %~dp0\xeniface\xeniface
rd /s /q %~dp0\xeniface\vs2022\Windows10Debug
rd /s /q %~dp0\xeniface\vs2022\Windows10Release
rd /s /q %~dp0\xeniface\vs2022\x64
rd /s /q %~dp0\xeniface\vs2022\package\Windows10Debug
rd /s /q %~dp0\xeniface\vs2022\package\Windows10Release
rd /s /q %~dp0\xeniface\vs2022\xenagent\x64
rd /s /q %~dp0\xeniface\vs2022\xencontrol\x64
rd /s /q %~dp0\xeniface\vs2022\xeniface\Windows10Debug
rd /s /q %~dp0\xeniface\vs2022\xeniface\Windows10Release
rd /s /q %~dp0\xeniface\vs2022\xeniface\x64

rd /s /q %~dp0\xennet\xennet
rd /s /q %~dp0\xennet\vs2022\Windows10Debug
rd /s /q %~dp0\xennet\vs2022\Windows10Release
rd /s /q %~dp0\xennet\vs2022\x64
rd /s /q %~dp0\xennet\vs2022\package\Windows10Debug
rd /s /q %~dp0\xennet\vs2022\package\Windows10Release
rd /s /q %~dp0\xennet\vs2022\xennet\Windows10Debug
rd /s /q %~dp0\xennet\vs2022\xennet\Windows10Release
rd /s /q %~dp0\xennet\vs2022\xennet\x64

rd /s /q %~dp0\xenvbd\xenvbd
rd /s /q %~dp0\xenvbd\vs2022\Windows10Debug
rd /s /q %~dp0\xenvbd\vs2022\Windows10Release
rd /s /q %~dp0\xenvbd\vs2022\x64
rd /s /q %~dp0\xenvbd\vs2022\package\Windows10Debug
rd /s /q %~dp0\xenvbd\vs2022\package\Windows10Release
rd /s /q %~dp0\xenvbd\vs2022\xencrsh\Windows10Debug
rd /s /q %~dp0\xenvbd\vs2022\xencrsh\Windows10Release
rd /s /q %~dp0\xenvbd\vs2022\xencrsh\x64
rd /s /q %~dp0\xenvbd\vs2022\xendisk\Windows10Debug
rd /s /q %~dp0\xenvbd\vs2022\xendisk\Windows10Release
rd /s /q %~dp0\xenvbd\vs2022\xendisk\x64
rd /s /q %~dp0\xenvbd\vs2022\xenvbd\Windows10Debug
rd /s /q %~dp0\xenvbd\vs2022\xenvbd\Windows10Release

rd /s /q %~dp0\xenvif\xenvif
rd /s /q %~dp0\xenvif\vs2022\Windows10Debug
rd /s /q %~dp0\xenvif\vs2022\Windows10Release
rd /s /q %~dp0\xenvif\vs2022\x64
rd /s /q %~dp0\xenvif\vs2022\package\Windows10Debug
rd /s /q %~dp0\xenvif\vs2022\package\Windows10Release
rd /s /q %~dp0\xenvif\vs2022\xenvif\Windows10Debug
rd /s /q %~dp0\xenvif\vs2022\xenvif\Windows10Release
rd /s /q %~dp0\xenvif\vs2022\xenvif\x64
