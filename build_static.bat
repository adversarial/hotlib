:: Windows build script for hotlib
:: x8esix

@echo off

set objects=

:: cleanup     
     FOR %%i in (*.o) DO del %%i
     IF EXIST .\Release\hotlib.lib del .\Release\hotlib.lib /Q

     FOR %%i in (*.c) DO (gcc -c %%i -std=c99 -Os -s -pedantic & ECHO Compiling %%i)
 
     ECHO.
     ECHO Linking library...
     ECHO.

     FOR %%i in (*.o) DO (call :concat %%i & ECHO Adding %%i to library)
     call :concat PEel32.lib

     ar rcs .\Release\hotlib.lib %objects%

ECHO.
ECHO Cleaning up...
ECHO.
    
     FOR %%i in (*.o) DO (del %%i & ECHO Deleting %%i...)

ECHO.
ECHO Compilation complete!
ECHO.
pause

:concat
set objects=%objects% %1
goto :eof