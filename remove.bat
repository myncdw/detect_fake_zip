@echo off
chcp 65001 >nul

echo 正在移除当前用户的右键菜单...
reg delete "HKCU\Software\Classes\*\shell\检测并提取伪装压缩包" /f >nul 2>nul

if errorlevel 1 (
    echo 注册表项不存在或删除失败。
    pause
    exit /b 1
) else (
    echo 成功。
    pause
    exit /b 0
)
