#include <windows.h>
#include <commctrl.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <richedit.h>

#pragma comment(lib, "comctl32.lib")

std::ofstream logFile("dark_editor.log", std::ios::out | std::ios::trunc);

void Log(const std::string& msg) {
    std::cout << msg << std::endl;
    if (logFile.is_open()) {
        logFile << msg << std::endl;
        logFile.flush();
    }
}

void AnalyzeTabControlChildren(HWND hTabControl) {
    Log("[ANALYSIS] Scanning SysTabControl32: " + std::to_string((uintptr_t)hTabControl));
    
    HWND parent = GetParent(hTabControl);
    Log("[ANALYSIS] Parent HWND: " + std::to_string((uintptr_t)parent));
    
    HWND hChild = GetWindow(hTabControl, GW_CHILD);
    if (!hChild) {
        Log("[ANALYSIS] No direct children found via GW_CHILD.");
    }
    
    EnumChildWindows(hTabControl, [](HWND hwnd, LPARAM lParam) -> BOOL {
        char className[256] = {0};
        GetClassNameA(hwnd, className, sizeof(className));
        char windowText[256] = {0};
        GetWindowTextA(hwnd, windowText, sizeof(windowText));
        
        Log("  [FOUND_CHILD] HWND: " + std::to_string((uintptr_t)hwnd) + 
            " | Class: " + className + 
            " | Text: '" + windowText + "'");
        return TRUE;
    }, 0);
    Log("[ANALYSIS] End scanning.");
}


struct EnumData {
    DWORD targetPid;
    std::vector<HWND> foundWindows;
};

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    DWORD windowPid = 0;
    GetWindowThreadProcessId(hwnd, &windowPid);
    if (windowPid == data->targetPid) {
        data->foundWindows.push_back(hwnd);
    }
    return TRUE;
}

DWORD FindProcessId(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(entry);
    std::cout << "  5. TEST E: Разведка SysTabControl321\n";
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

int main() {
    SetConsoleOutputCP(65001);
    Log("=== DarkSC2 Editor RichEdit Isolation Tests ===");

    std::cout << "\nВыберите вариант теста (1-4):\n";
    std::cout << "  1. TEST A: Только безопасное чтение (GetClassName, GetWindowText, GetClientRect) без изменения цветов\n";
    std::cout << "  2. TEST B: Только EM_SETBKGNDCOLOR -> RGB(30,30,30) + repaint\n";
    std::cout << "  3. TEST C: Только EM_SETCHARFORMAT (цвет текста RGB(220,220,220)), без изменения фона\n";
    std::cout << "  4. TEST D: Только безопасное чтение состояния RichEdit (без вызова небезопасных API)\n";
    std::cout << "Ваш выбор (1-4): ";

    int choice = 1;
    std::cin >> choice;

    DWORD pid = FindProcessId(L"SC2Editor_x64.exe");
    if (pid == 0) {
        Log("[ERROR] SC2Editor_x64.exe not found!");
        std::cout << "Press Enter to exit..."; std::cin.get();
        return 1;
    }

    Log("[INFO] Found SC2Editor_x64.exe PID: " + std::to_string(pid));

    EnumData enumData;
    enumData.targetPid = pid;
    EnumChildWindows(GetDesktopWindow(), EnumChildProc, (LPARAM)&enumData);
    Log("[INFO] Total child windows found: " + std::to_string(enumData.foundWindows.size()));

    HMODULE hUxTheme = LoadLibraryA("uxtheme.dll");
    typedef HRESULT(WINAPI* pfnSetWindowTheme)(HWND, LPCWSTR, LPCWSTR);
    pfnSetWindowTheme SetWindowThemeFn = hUxTheme ? (pfnSetWindowTheme)GetProcAddress(hUxTheme, "SetWindowTheme") : nullptr;


        // Убрали ошибочные блоки


    int richEditCounter = 0;

    for (HWND hwnd : enumData.foundWindows) {
        if (!IsWindow(hwnd)) continue;

        char className[256] = {0};
        GetClassNameA(hwnd, className, sizeof(className));
        std::string cName(className);

        if (cName.empty()) continue;

        // Разведка
        if (cName == "SysTabControl32" && choice == 5) {
            AnalyzeTabControlChildren(hwnd);
        }

        // Фокусируемся конкретно на RichEdit20W и базовых элементах для чистоты теста
        if (cName == "SysTreeView32") {
            if (choice == 2 || choice == 3) {
                if (SetWindowThemeFn) SetWindowThemeFn(hwnd, L"DarkMode_Explorer", NULL);
                TreeView_SetBkColor(hwnd, RGB(30, 30, 30));
                TreeView_SetTextColor(hwnd, RGB(220, 220, 220));
                InvalidateRect(hwnd, NULL, TRUE);
                UpdateWindow(hwnd);
            }
            continue;
        }
        else if (cName == "SysListView32") {
            if (choice == 2 || choice == 3) {
                if (SetWindowThemeFn) SetWindowThemeFn(hwnd, L"DarkMode_Explorer", NULL);
                ListView_SetBkColor(hwnd, RGB(30, 30, 30));
                ListView_SetTextBkColor(hwnd, RGB(30, 30, 30));
                ListView_SetTextColor(hwnd, RGB(220, 220, 220));
                InvalidateRect(hwnd, NULL, TRUE);
                UpdateWindow(hwnd);
            }
            continue;
        }

        if (cName != "RichEdit20W") continue;

        richEditCounter++;
        char windowText[256] = {0};
        GetWindowTextA(hwnd, windowText, sizeof(windowText));
        std::string wText(windowText);
        std::string hwndStr = std::to_string((uintptr_t)hwnd);

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        Log("[BEGIN] TEST " + std::to_string(choice) + " | HWND: " + hwndStr + " | RichEdit #" + std::to_string(richEditCounter) + " | Text: '" + wText + "'");

        if (choice == 1) {
            // TEST A: Только чтение (ClassName, WindowText, ClientRect)
            Log("[TEST A SUCCESS] HWND: " + hwndStr + " | ClientRect w=" + std::to_string(rcClient.right) + " h=" + std::to_string(rcClient.bottom));
        }
        else if (choice == 2) {
            // TEST B: Только EM_SETBKGNDCOLOR -> RGB(30,30,30) + repaint
            SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, (LPARAM)RGB(30, 30, 30));
            InvalidateRect(hwnd, NULL, TRUE);
            UpdateWindow(hwnd);
            Log("[TEST B SUCCESS] HWND: " + hwndStr + " | BG set to RGB(30,30,30)");
        }
        else if (choice == 3) {
            // TEST C: Только EM_SETCHARFORMAT (цвет текста), без фона
            CHARFORMAT2W cf;
            ZeroMemory(&cf, sizeof(cf));
            cf.cbSize = sizeof(CHARFORMAT2W);
            cf.dwMask = CFM_COLOR;
            cf.crTextColor = RGB(220, 220, 220);
            SendMessage(hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
            InvalidateRect(hwnd, NULL, TRUE);
            UpdateWindow(hwnd);
            Log("[TEST C SUCCESS] HWND: " + hwndStr + " | Text color set to RGB(220,220,220)");
        }
        else if (choice == 4) {
            // TEST D: Безопасное чтение состояния (без изменения)
            GETTEXTLENGTHEX gtl = {GTL_DEFAULT, 1200};
            LRESULT textLen = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
            Log("[TEST D SUCCESS] HWND: " + hwndStr + " | Text Length: " + std::to_string(textLen));
        }

        Log("[END] HWND: " + hwndStr);
    }

    if (hUxTheme) FreeLibrary(hUxTheme);
    Log("=== Done. Check dark_editor.log ===");
    std::cout << "\nTest completed. Press Enter to exit...";
    std::cin.ignore();
    std::cin.get();
    return 0;
}

