#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>

struct WindowInfo {
    HWND hwnd;
    std::string className;
    std::string windowText;
};

std::vector<WindowInfo> foundWindows;

void ScanAllWindows(HWND hwnd) {
    char className[256] = {0};
    char windowText[256] = {0};
    GetClassNameA(hwnd, className, sizeof(className));
    GetWindowTextA(hwnd, windowText, sizeof(windowText));

    WindowInfo info = {hwnd, className, windowText};
    foundWindows.push_back(info);

    std::cout << "[" << foundWindows.size() - 1 << "] " << (void*)hwnd 
              << " | Class: " << className 
              << " | Text: '" << windowText << "'" << std::endl;
}

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    ScanAllWindows(hwnd);
    return TRUE;
}

BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lParam) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == (DWORD)lParam) {
        ScanAllWindows(hwnd);
        EnumChildWindows(hwnd, EnumChildProc, 0);
    }
    return TRUE;
}

int main() {
    SetConsoleOutputCP(65001);
    std::cout << "--- Интерактивный обозреватель окон SC2 ---" << std::endl;
    
    DWORD pid = 0;
    std::cout << "Введите PID: ";
    std::cin >> pid;

    EnumWindows(EnumProc, (LPARAM)pid);

    while (true) {
        std::cout << "\nВведите индекс окна для подробностей (или -1 для выхода, -2 для обновления): ";
        int index;
        std::cin >> index;
        if (index == -1) break;
        if (index == -2) {
            foundWindows.clear();
            EnumWindows(EnumProc, (LPARAM)pid);
            continue;
        }

        if (index >= 0 && index < (int)foundWindows.size()) {
            HWND h = foundWindows[index].hwnd;
            std::cout << "Выбрано окно: " << (void*)h << " (Class: " << foundWindows[index].className << ")" << std::endl;
            std::cout << "1. Показать стили" << std::endl;
            std::cout << "2. Показать цепочку родителей" << std::endl;
            std::cout << "3. Показать прямых детей" << std::endl;
            
            int action;
            std::cin >> action;
            std::cout << "Выберите действие (1-3): ";
            
            if (action == 1) {
                LONG_PTR style = GetWindowLongPtrA(h, GWL_STYLE);
                std::cout << "Стиль: 0x" << std::hex << style << std::dec << std::endl;
            } else if (action == 2) {
                HWND parent = GetParent(h);
                std::cout << "Цепочка родителей:" << std::endl;
                while (parent) {
                    char pClass[256] = {0};
                    GetClassNameA(parent, pClass, sizeof(pClass));
                    std::cout << "  " << (void*)parent << " (" << pClass << ")" << std::endl;
                    parent = GetParent(parent);
                }
            } else if (action == 3) {
                std::cout << "Прямые дети:" << std::endl;
                HWND child = GetWindow(h, GW_CHILD);
                while (child) {
                    char cClass[256] = {0};
                    GetClassNameA(child, cClass, sizeof(cClass));
                    std::cout << "  " << (void*)child << " (" << cClass << ")" << std::endl;
                    child = GetWindow(child, GW_HWNDNEXT);
                }
            }
        } else {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << "Неверный индекс." << std::endl;
        }
    }
    return 0;
}
