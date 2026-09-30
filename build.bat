@echo off
chcp 65001 > nul
echo [BUILD] Начинаем компиляцию DarkSC2...

:: Проверяем, передан ли путь к cl.exe или настроено ли окружение
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Компилятор cl.exe не найден в PATH. Пытаемся найти Visual Studio...
    
    :: Стандартные пути к vcvarsall.bat для VS 2019 / 2022
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else (
        echo [ERROR] Не удалось автоматически найти Visual Studio.
        echo Пожалуйста, укажи расположение cl.exe или запусти этот батник из командной строки Developer Command Prompt для VS.
        pause
        exit /b 1
    )
)

echo [BUILD] Компиляция main.cpp в dark_sc2.exe ...
cl.exe /EHsc /W4 /O2 main.cpp /link user32.lib gdi32.lib comctl32.lib /OUT:dark_sc2.exe

if %errorlevel% neq 0 (
    echo [ERROR] Ошибка компиляции!
    pause
    exit /b 1
)

echo [SUCCESS] Сборка завершена! Создан файл dark_sc2.exe
pause
echo [BUILD] Компиляция explorer.cpp в explorer.exe ...
cl.exe /EHsc /W4 /O2 explorer.cpp /link user32.lib gdi32.lib comctl32.lib /OUT:explorer.exe

