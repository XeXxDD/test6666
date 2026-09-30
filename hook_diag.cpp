#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <fstream>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")

extern "C" IMAGE_DOS_HEADER __ImageBase;

static HWND  g_hDialog = nullptr;
static HWND  g_hSet = nullptr;
static HWND  g_hEquals = nullptr;
static HBRUSH g_hDarkBrush = nullptr;
static WNDPROC g_originalWndProc = nullptr;
static HWND g_hVariable = nullptr;
static HWND g_hValue = nullptr;

static std::ofstream g_log;


void Log(const std::string& text)
{
    if (g_log.is_open())
    {
        g_log << text << std::endl;
        g_log.flush();
    }    
}



std::string HwndToString(HWND hwnd)
{
    char buffer[32];
    sprintf_s(buffer, sizeof(buffer), "0x%p", hwnd);
    return buffer;
}

std::string GetClassNameString(HWND hwnd)
{
    char buffer[256] = {};
    GetClassNameA(hwnd, buffer, sizeof(buffer));
    return buffer;
}

std::string GetWindowTextString(HWND hwnd)
{
    char buffer[512] = {};
    GetWindowTextA(hwnd, buffer, sizeof(buffer));
    return buffer;
}


// ------------------------------------------------------------
// Ищем прямого child по Class + Text
// ------------------------------------------------------------

struct FindChildData
{
    const char* className;
    const char* windowText;
    HWND result;
};

BOOL CALLBACK FindChildProc(HWND hwnd, LPARAM lParam)
{
    FindChildData* data = reinterpret_cast<FindChildData*>(lParam);

    if (GetParent(hwnd) != g_hDialog)
        return TRUE;

    char className[256] = {};
    char windowText[512] = {};

    GetClassNameA(hwnd, className, sizeof(className));
    GetWindowTextA(hwnd, windowText, sizeof(windowText));

    if (strcmp(className, data->className) == 0 &&
        strcmp(windowText, data->windowText) == 0)
    {
        data->result = hwnd;
        return FALSE;
    }

    return TRUE;
}

HWND FindDirectChild(const char* className, const char* windowText)
{
    FindChildData data{};
    data.className = className;
    data.windowText = windowText;
    data.result = nullptr;

    EnumChildWindows(g_hDialog, FindChildProc, reinterpret_cast<LPARAM>(&data));

    return data.result;
}


// ------------------------------------------------------------
// Ищем #32770 внутри текущего процесса
// ------------------------------------------------------------

BOOL CALLBACK FindDialogProc(HWND hwnd, LPARAM)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    if (pid != GetCurrentProcessId())
        return TRUE;

    char className[256] = {};
    GetClassNameA(hwnd, className, sizeof(className));

    if (strcmp(className, "#32770") != 0)
        return TRUE;

    // Нас интересует именно dialog, содержащий наши Static.
    g_hDialog = hwnd;

    HWND hSet = FindDirectChild("Static", "Set ");
    HWND hEquals = FindDirectChild("Static", " = ");

    if (hSet && hEquals)
    {
        g_hDialog = hwnd;
        g_hSet = hSet;
        g_hEquals = hEquals;

        // НОВОЕ
        g_hVariable = FindDirectChild("Button", "Variable");
        g_hValue    = FindDirectChild("Button", "Value");

        Log("[FOUND] Variable: " + HwndToString(g_hVariable));
        Log("[FOUND] Value:    " + HwndToString(g_hValue));

        return FALSE;
    }

    g_hDialog = nullptr;
    return TRUE;
}


// ------------------------------------------------------------
// Наш callback
// ------------------------------------------------------------

LRESULT CALLBACK DialogWndProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
if (uMsg == WM_DRAWITEM)
{
    auto* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);

    if (dis && dis->hwndItem)
    {
        HWND hwndItem = dis->hwndItem;

        LONG_PTR style = GetWindowLongPtrW(
            hwndItem,
            GWL_STYLE
        );

        LONG_PTR exStyle = GetWindowLongPtrW(
            hwndItem,
            GWL_EXSTYLE
        );

        HWND parent = GetParent(hwndItem);

        int ctrlId = GetDlgCtrlID(hwndItem);

        RECT rcScreen{};
        RECT rcDialog{};

        GetWindowRect(hwndItem, &rcScreen);

        POINT pt{};
        pt.x = rcScreen.left;
        pt.y = rcScreen.top;

        if (g_hDialog)
        {
            ScreenToClient(g_hDialog, &pt);

            rcDialog.left = pt.x;
            rcDialog.top = pt.y;
            rcDialog.right =
                pt.x + (rcScreen.right - rcScreen.left);
            rcDialog.bottom =
                pt.y + (rcScreen.bottom - rcScreen.top);
        }

        int width =
            rcScreen.right - rcScreen.left;

        int height =
            rcScreen.bottom - rcScreen.top;

        wchar_t text[256]{};

        GetWindowTextW(
            hwndItem,
            text,
            static_cast<int>(std::size(text))
        );

        wchar_t className[256]{};
        GetClassNameW(
            hwndItem,
            className,
            static_cast<int>(std::size(className))
        );

        wchar_t parentClass[256]{};
        GetClassNameW(
            parent,
            parentClass,
            static_cast<int>(std::size(parentClass))
        );

        int parentId = GetDlgCtrlID(parent);

        LONG_PTR parentStyle = GetWindowLongPtrW(
            parent,
            GWL_STYLE
        );

        std::ostringstream ss;

        char textA[256]{};
        char classNameA[256]{};
        char parentClassA[256]{};

        WideCharToMultiByte(
            CP_ACP, 0,
            text, -1,
            textA, sizeof(textA),
            nullptr, nullptr
        );

        WideCharToMultiByte(
            CP_ACP, 0,
            className, -1,
            classNameA, sizeof(classNameA),
            nullptr, nullptr
        );

        WideCharToMultiByte(
            CP_ACP, 0,
            parentClass, -1,
            parentClassA, sizeof(parentClassA),
            nullptr, nullptr
        );

        ss << "[WM_DRAWITEM]"
        << " hwnd=0x" << std::hex
        << reinterpret_cast<uintptr_t>(hwndItem)
        << " text='" << textA << "'"
        << " id=" << std::dec << GetDlgCtrlID(hwndItem)
        << " style=0x" << std::hex << GetWindowLongPtrW(hwndItem, GWL_STYLE)
        << " exStyle=0x" << GetWindowLongPtrW(hwndItem, GWL_EXSTYLE)
        << " parent=0x"
        << reinterpret_cast<uintptr_t>(GetParent(hwndItem))
        << " class='" << classNameA << "'"
        << " parentClass='" << parentClassA << "'";

        Log(ss.str());
    }
}
    if (uMsg == WM_CTLCOLORSTATIC)
    {
        HWND hStatic = reinterpret_cast<HWND>(lParam);

        Log(
            "[WM_CTLCOLORSTATIC] child=" +
            HwndToString(hStatic) +
            " class=" +
            GetClassNameString(hStatic) +
            " text='" +
            GetWindowTextString(hStatic) +
            "'"
        );

        if (GetParent(hStatic) == g_hDialog)
        {
            HDC hdc = reinterpret_cast<HDC>(wParam);

            SetTextColor(hdc, RGB(220, 220, 220));
            SetBkColor(hdc, RGB(30, 30, 30));
            SetBkMode(hdc, OPAQUE);

            return reinterpret_cast<LRESULT>(g_hDarkBrush);
        }
    }

    return CallWindowProcW(
        g_originalWndProc,
        hwnd,
        uMsg,
        wParam,
        lParam
    );
}
// ------------------------------------------------------------
// Установка subclass
// ------------------------------------------------------------

DWORD WINAPI InstallThread(LPVOID)
{
    // Небольшая задержка нужна только для того,
    // чтобы SC2 успел закончить загрузку окна.
    Sleep(1000);

    char path[MAX_PATH] = {};

    GetModuleFileNameA(
        reinterpret_cast<HMODULE>(&__ImageBase),
        path,
        sizeof(path)
    );

    std::string logPath = path;

    size_t slash = logPath.find_last_of("\\/");

    if (slash != std::string::npos)
        logPath.resize(slash + 1);

    logPath += "hook_diag.log";

    g_log.open(
        logPath,
        std::ios::out | std::ios::trunc
    );

    Log("=== hook_diag started ===");

    Log(
        "[INFO] Current PID: " +
        std::to_string(GetCurrentProcessId())
    );

    // --------------------------------------------------------
    // Ищем target dialog
    // --------------------------------------------------------

    EnumWindows(
        FindDialogProc,
        0
    );

    if (!g_hDialog)
    {
        Log(
            "[ERROR] Target #32770 dialog not found."
        );

        return 0;
    }

    // --------------------------------------------------------
    // Создаём кисть для тёмного фона
    // --------------------------------------------------------

    g_hDarkBrush =
        CreateSolidBrush(
            RGB(30, 30, 30)
        );

    if (!g_hDarkBrush)
    {
        Log(
            "[ERROR] CreateSolidBrush failed. Error=" +
            std::to_string(GetLastError())
        );

        return 0;
    }

    // --------------------------------------------------------
    // Сохраняем оригинальный WndProc
    // и устанавливаем наш
    // --------------------------------------------------------

    SetLastError(ERROR_SUCCESS);

    g_originalWndProc =
        reinterpret_cast<WNDPROC>(
            SetWindowLongPtrW(
                g_hDialog,
                GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(
                    DialogWndProc
                )
            )
        );

    if (!g_originalWndProc)
    {
        DWORD error = GetLastError();

        Log(
            "[ERROR] SetWindowLongPtrW failed. Error=" +
            std::to_string(error)
        );

        DeleteObject(g_hDarkBrush);
        g_hDarkBrush = nullptr;

        return 0;
    }

    Log(
        "[SUCCESS] Classic WNDPROC subclass installed."
    );

    Log(
        "[INFO] Waiting for WM_CTLCOLORSTATIC..."
    );

    return 0;
}

// ------------------------------------------------------------
// DLL entry
// ------------------------------------------------------------

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD reason,
    LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread = CreateThread(
            nullptr,
            0,
            InstallThread,
            nullptr,
            0,
            nullptr
        );

        if (hThread)
            CloseHandle(hThread);
    }

    else if (reason == DLL_PROCESS_DETACH)
    {
        if (g_hDialog && g_originalWndProc)
        {
            SetWindowLongPtrW(
                g_hDialog,
                GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(g_originalWndProc)
            );

            g_originalWndProc = nullptr;
        }

        if (g_hDarkBrush)
        {
            DeleteObject(g_hDarkBrush);
            g_hDarkBrush = nullptr;
        }

        if (g_log.is_open())
            g_log.close();
    }

    return TRUE;
}