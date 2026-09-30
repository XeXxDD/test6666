#include <windows.h>
#include <commctrl.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Глобальные переменные для взаимодействия с хуком
HWND targetParentHwnd = NULL;
HHOOK hHook = NULL;
std::ofstream logFile("dark_editor.log", std::ios::out | std::ios::app);

void Log(const std::string& msg) {
    if (logFile.is_open()) {
        logFile << msg << std::endl;
        logFile.flush();
    }
}

// Callback для поиска окон
struct EnumData {
    DWORD targetPid;
    HWND hSysTab = NULL;
    HWND hTargetParent = NULL;
};

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    char className[256];
    GetClassNameA(hwnd, className, sizeof(className));
    
    if (std::string(className) == "SysTabControl32") {
        data->hSysTab = hwnd;
        data->hTargetParent = GetParent(hwnd);
        return FALSE; // Нашли
    }
    return TRUE;
}

// Хук-процедура
LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        CWPSTRUCT* pCwp = (CWPSTRUCT*)lParam;
        if (pCwp->message == WM_DRAWITEM) {
            // Проверяем, что сообщение для нашего целевого родителя
            if (pCwp->hwnd == targetParentHwnd) {
                DRAWITEMSTRUCT* pDis = (DRAWITEMSTRUCT*)pCwp->lParam;
                Log("[WM_DRAWITEM] Hwnd=" + std::to_string((uintptr_t)pCwp->hwnd) +
                    " | CtlType=" + std::to_string(pDis->CtlType) +
                    " | CtlID=" + std::to_string(pDis->CtlID) +
                    " | itemState=" + std::to_string(pDis->itemState) +
                    " | itemAction=" + std::to_string(pDis->itemAction) +
                    " | HwndItem=" + std::to_string((uintptr_t)pDis->hwndItem) +
                    " | rcItem=[" + std::to_string(pDis->rcItem.left) + "," + std::to_string(pDis->rcItem.top) +
                    "," + std::to_string(pDis->rcItem.right) + "," + std::to_string(pDis->rcItem.bottom) + "]");
            }
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

int main() {
    // 1. Поиск процесса SC2Editor
    // (Логика поиска через CreateToolhelp32Snapshot аналогична уже имеющейся)
    // Допустим, мы нашли PID и получили targetParentHwnd
    
    Log("--- Start Diagnostics ---");
    // Здесь должна быть логика поиска PID и окна (пропущено для краткости)
    // ...
    
    if (targetParentHwnd) {
        DWORD threadId = GetWindowThreadProcessId(targetParentHwnd, NULL);
        hHook = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, NULL, threadId);
        
        if (hHook) {
            Log("Hook installed on thread: " + std::to_string(threadId));
            std::cout << "Hook active. Press Enter to stop..." << std::endl;
            std::cin.get();
            UnhookWindowsHookEx(hHook);
            Log("Hook removed.");
        } else {
            Log("Failed to install hook! Error: " + std::to_string(GetLastError()));
        }
    }

    return 0;
}
