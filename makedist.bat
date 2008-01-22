@echo off
xcopy target\* dist /E /EXCLUDE:exclude.txt /D /Y
copy doc\*.txt dist
