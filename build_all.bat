@echo off
chcp 65001 > nul
echo [BUILD] Начинаем компиляцию...

:: Настройка окружения VS
if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
)

echo [BUILD] Компиляция hook_diag.cpp в hook_diag.dll ...
cl.exe /LD /EHsc /W4 /O2 hook_diag.cpp /link user32.lib /OUT:hook_diag.dll

echo [BUILD] Компиляция main.cpp в dark_sc2.exe ...
cl.exe /EHsc /W4 /O2 main.cpp /link user32.lib gdi32.lib comctl32.lib /OUT:dark_sc2.exe

echo [SUCCESS] Сборка завершена!
pause
