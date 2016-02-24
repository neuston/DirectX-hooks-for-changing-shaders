REM Delete everything that could be in the target folder, including debug items.
REM If something is not there, the DEL skips without error.
REM Also deletes the ShaderCache, ShaderFixes, ShaderFromGame folders

del fix-readme.txt

del d3d11.dll
del d3d11_log.txt

del nvapi.dll
del nvapi64.dll
del nvapi_log.txt

del d3dx.ini

rmdir /s /q ShaderFixes

del uninstall.bat