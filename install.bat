@echo off
chcp 65001 >nul

REM 安装右键菜单（当前用户，仅文件）
REM 请确保 detect_fake_zip.exe 与本脚本在同一目录，或修改 TARGET_EXE 指向正确路径。

set "TARGET_EXE=%~dp0detect_fake_zip.exe"

if not exist "%TARGET_EXE%" (
    echo 未找到 "%TARGET_EXE%"
    echo 请确保 detect_fake_zip.exe 与本脚本在同一目录，或修改 TARGET_EXE 指向正确路径。
    pause
    exit /b 1
)

echo 正在添加...
reg add "HKCU\Software\Classes\*\shell\检测并提取伪装压缩包" /ve /d "检测并提取伪装压缩包" /f >nul
reg add "HKCU\Software\Classes\*\shell\检测并提取伪装压缩包" /v "Icon" /d "%TARGET_EXE%" /f >nul
reg add "HKCU\Software\Classes\*\shell\检测并提取伪装压缩包\command" /ve /d "\"%TARGET_EXE%\" \"%%1\"" /f >nul

if errorlevel 1 (
    echo 失败。
    pause
    exit /b 1
) else (
    echo 成功。
    pause
    exit /b 0
)
