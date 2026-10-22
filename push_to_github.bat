@echo off
setlocal enabledelayedexpansion
title Push Windows-Registry-Monitoring to GitHub

echo ==============================================================================
echo       Windows Registry Monitoring System - GitHub Push Assistant
echo                       Publisher: MADE BY PIYUSH
echo ==============================================================================
echo.

set GITHUB_USER=Made-by-Piyush99
set REPO_NAME=Windows-Registry-Monitoring

echo Target Repository: https://github.com/%GITHUB_USER%/%REPO_NAME%
echo.
echo Select Authentication Method:
echo   [1] Web Browser Login (Git Credential Manager - Recommended)
echo   [2] GitHub Personal Access Token (PAT)
echo.
set /p AUTH_CHOICE="Enter choice [1 or 2, default: 1]: "
if "%AUTH_CHOICE%"=="" set AUTH_CHOICE=1

if "%AUTH_CHOICE%"=="2" (
    echo.
    set /p GITHUB_PAT="Enter your GitHub Personal Access Token: "
    if "!GITHUB_PAT!"=="" (
        echo [ERROR] Token cannot be empty.
        pause
        exit /b 1
    )
    set REMOTE_URL=https://!GITHUB_PAT!@github.com/%GITHUB_USER%/%REPO_NAME%.git
) else (
    set REMOTE_URL=https://%GITHUB_USER%@github.com/%GITHUB_USER%/%REPO_NAME%.git
)

echo.
echo [*] Configuring remote origin...
git remote remove origin 2>nul
git remote add origin %REMOTE_URL%

echo [*] Initializing Git LFS...
git lfs install

echo.
echo [*] Pushing 'main' branch to GitHub...
git push -u origin main

echo.
echo [*] Pushing to 'piyush' branch to update existing remote branch...
git push origin main:piyush --force

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ==============================================================================
    echo [SUCCESS] All files and branches successfully pushed to:
    echo https://github.com/%GITHUB_USER%/%REPO_NAME%
    echo ==============================================================================
) else (
    echo.
    echo ==============================================================================
    echo [WARNING] If push was denied or timed out:
    echo 1. Verify you are logged into GitHub as '%GITHUB_USER%' in your browser.
    echo 2. Or generate a Personal Access Token with 'repo' scope at:
    echo    https://github.com/settings/tokens
    echo    Then run this script and choose Option 2.
    echo ==============================================================================
)

echo.
pause
