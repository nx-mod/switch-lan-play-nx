@echo off
setlocal EnableDelayedExpansion
title switch-lan-play-nx Builder Menu

rem ---------------------------------------------------------------
rem Interactive build menu for switch-lan-play-nx (bsd:u mitm bridge).
rem Uses the devkitPro MSYS2 environment (C:\devkitPro\msys2).
rem ---------------------------------------------------------------

set "BASH=C:\devkitPro\msys2\usr\bin\bash.exe"
set "SCRIPT=/c/PROJECTS/switch/switch-cfw/switch-lan-play-nx/build.sh"
set "JOBS=2"

if not exist "%BASH%" (
    echo ERROR: devkitPro MSYS2 bash not found at:
    echo   %BASH%
    echo Install devkitPro first: https://devkitpro.org
    pause
    exit /b 1
)

:menu
cls
echo ============================================
echo      switch-lan-play-nx Build Menu
echo      Repo: C:\PROJECTS\switch\switch-cfw\switch-lan-play-nx
echo      Jobs: %JOBS%
echo ============================================
echo.
echo   1) Build                  (all; produces .nsp + overlay\overlay.ovl)
echo   2) Build + SD zip          (dist, packages _ZIPS_/switch-lan-play-nx-release.zip)
echo   3) Dry run                 (shows what would build, no compile)
echo   4) Set job count           (currently %JOBS%)
echo   5) Clean                   (remove build artifacts)
echo.
echo   0) Quit
echo.
set /p CHOICE="Select an option: "

if "%CHOICE%"=="1" ( set "TARGET=all" & goto build )
if "%CHOICE%"=="2" ( set "TARGET=dist" & goto build )
if "%CHOICE%"=="3" ( set "TARGET=all" & set "DRYRUN=1" & goto build )
if "%CHOICE%"=="4" goto jobs
if "%CHOICE%"=="5" ( set "TARGET=clean" & goto build )
if "%CHOICE%"=="0" exit /b 0
echo Invalid choice. & timeout /t 1 >nul & goto menu

:jobs
echo.
set /p JOBS="Enter job count (parallel make jobs): "
if "%JOBS%"=="" set "JOBS=2"
goto menu

:build
echo.
echo == Building: target=%TARGET% jobs=%JOBS% ==
if defined DRYRUN (
    "%BASH%" -lc "bash '%SCRIPT%' '%TARGET%' '%JOBS%' --dryrun"
) else (
    "%BASH%" -lc "bash '%SCRIPT%' '%TARGET%' '%JOBS%'"
)
echo.
if errorlevel 1 (
    echo == BUILD FAILED - see output above ==
) else (
    echo == DONE ==
)
set "DRYRUN="
pause
goto menu
