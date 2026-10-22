@echo off
setlocal enabledelayedexpansion
title Push Windows-Registry-Monitoring to GitHub

echo ==============================================================================
echo       Windows Registry Monitoring System - GitHub Push Assistant
echo                       Publisher: MADE BY PIYUSH
echo ==============================================================================
echo.

set /p GITHUB_USER="Enter your GitHub Username (e.g. your-name): "
if "%GITHUB_USER%"=="" (
    echo [ERROR] GitHub username cannot be empty!
    pause
    exit /b 1
)

set REPO_NAME=Windows-Registry-Monitoring
set REMOTE_URL=https://github.com/%GITHUB_USER%/%REPO_NAME%.git

echo.
echo Target Repository: %REMOTE_URL%
echo.

git remote remove origin 2>nul
git remote add origin %REMOTE_URL%
git branch -M main

echo [*] Initializing Git LFS for binary deliverables...
git lfs install

echo [*] Pushing main branch to GitHub...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ==============================================================================
    echo [SUCCESS] Successfully pushed all files to:
    echo %REMOTE_URL%
    echo ==============================================================================
) else (
    echo.
    echo ==============================================================================
    echo [NOTE] If authentication is required or the remote repository does not exist:
    echo 1. Ensure you have created the repository on GitHub:
    echo    https://github.com/new (Name: %REPO_NAME%)
    echo 2. Check your GitHub Personal Access Token (PAT) or credentials.
    echo ==============================================================================
)

echo.
pause
