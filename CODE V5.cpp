#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <fstream>
#include <sstream>
#include <uxtheme.h>
#include <vsstyle.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "uxtheme.lib")

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

// ------------------------------------------------------------
// V23: IAT hook для DrawThemeTextEx
// ------------------------------------------------------------

using DrawThemeTextEx_t = HRESULT (WINAPI*)(
    HTHEME,
    HDC,
    int,
    int,
    LPCWSTR,
    int,
    DWORD,
    LPRECT,
    const DTTOPTS*
);

static DrawThemeTextEx_t g_originalDrawThemeTextEx = nullptr;

HRESULT WINAPI HookDrawThemeTextEx(
    HTHEME hTheme,
    HDC hdc,
    int iPartId,
    int iStateId,
    LPCWSTR pszText,
    int cchText,
    DWORD dwTextFlags,
    LPRECT pRect,
    const DTTOPTS* pOptions)
{
    std::ostringstream ss;

    ss << "[V23_DRAW_THEME_TEXT_EX]"
       << " hTheme=" << hTheme
       << " hdc=" << hdc
       << " part=" << iPartId
       << " state=" << iStateId
       << " flags=0x" << std::hex << dwTextFlags;

    if (pszText != nullptr)
    {
        std::wstring text;

        if (cchText < 0)
            text = pszText;
        else
            text.assign(pszText, pszText + cchText);

        ss << " text=\"";

        for (wchar_t ch : text)
        {
            if (ch >= 32 && ch <= 126)
                ss << static_cast<char>(ch);
            else
                ss << "?";
        }

        ss << "\"";
    }

    if (pRect != nullptr)
    {
        ss << " rect=("
           << std::dec
           << pRect->left << ","
           << pRect->top << ")-("
           << pRect->right << ","
           << pRect->bottom << ")";
    }

    if (pOptions != nullptr)
    {
        ss << " optsSize=" << pOptions->dwSize
           << " optsFlags=0x"
           << std::hex
           << pOptions->dwFlags;

        if (pOptions->dwFlags & DTT_TEXTCOLOR)
        {
            ss << " crText=0x"
               << std::hex
               << pOptions->crText;
        }
    }
    else
    {
        ss << " opts=null";
    }

    Log(ss.str());

    return g_originalDrawThemeTextEx(
        hTheme,
        hdc,
        iPartId,
        iStateId,
        pszText,
        cchText,
        dwTextFlags,
        pRect,
        pOptions
    );
    
    bool InstallDrawThemeTextExHook()
    {
        HMODULE hExe = GetModuleHandleW(nullptr);

        if (!hExe)
        {
            Log("[V23] GetModuleHandleW(nullptr) failed.");
            return false;
        }

        auto base = reinterpret_cast<BYTE*>(hExe);

        auto dos =
            reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            Log("[V23] Invalid DOS header.");
            return false;
        }

        auto nt =
            reinterpret_cast<IMAGE_NT_HEADERS64*>(
                base + dos->e_lfanew
            );

        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            Log("[V23] Invalid NT header.");
            return false;
        }

        const auto& importDir =
            nt->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_IMPORT
            ];

        if (importDir.VirtualAddress == 0)
        {
            Log("[V23] No import directory.");
            return false;
        }

        auto importDesc =
            reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                base + importDir.VirtualAddress
            );

        for (; importDesc->Name != 0; ++importDesc)
        {
            const char* dllName =
                reinterpret_cast<const char*>(
                    base + importDesc->Name
                );

            if (_stricmp(dllName, "uxtheme.dll") != 0)
                continue;

            if (importDesc->OriginalFirstThunk == 0)
            {
                Log("[V23] OriginalFirstThunk is null.");
                return false;
            }

            auto firstThunk =
                reinterpret_cast<IMAGE_THUNK_DATA64*>(
                    base + importDesc->FirstThunk
                );

            auto originalThunk =
                reinterpret_cast<IMAGE_THUNK_DATA64*>(
                    base + importDesc->OriginalFirstThunk
                );

            for (; originalThunk->u1.AddressOfData != 0;
                ++originalThunk, ++firstThunk)
            {
                if (IMAGE_SNAP_BY_ORDINAL64(
                        originalThunk->u1.Ordinal))
                {
                    continue;
                }

                auto importByName =
                    reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        base + originalThunk->u1.AddressOfData
                    );

                const char* functionName =
                    reinterpret_cast<const char*>(
                        importByName->Name
                    );

                if (strcmp(functionName, "DrawThemeTextEx") != 0)
                    continue;

                g_originalDrawThemeTextEx =
                    reinterpret_cast<DrawThemeTextEx_t>(
                        firstThunk->u1.Function
                    );

                DWORD oldProtect = 0;

                if (!VirtualProtect(
                        &firstThunk->u1.Function,
                        sizeof(ULONGLONG),
                        PAGE_READWRITE,
                        &oldProtect))
                {
                    Log(
                        "[V23] VirtualProtect failed. Error=" +
                        std::to_string(GetLastError())
                    );

                    return false;
                }

                firstThunk->u1.Function =
                    reinterpret_cast<ULONGLONG>(
                        &HookDrawThemeTextEx
                    );

                DWORD dummy = 0;

                VirtualProtect(
                    &firstThunk->u1.Function,
                    sizeof(ULONGLONG),
                    oldProtect,
                    &dummy
                );

                FlushInstructionCache(
                    GetCurrentProcess(),
                    nullptr,
                    0
                );

                std::ostringstream ss;

                ss << "[V23] DrawThemeTextEx IAT hook installed. Original="
                << reinterpret_cast<void*>(
                        g_originalDrawThemeTextEx
                    );

                Log(ss.str());

                return true;
            }
        }

        Log("[V23] DrawThemeTextEx import NOT FOUND.");
        return false;
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
        DRAWITEMSTRUCT* dis =
            reinterpret_cast<DRAWITEMSTRUCT*>(lParam);

        if (dis != nullptr &&
            dis->CtlType == ODT_BUTTON &&
            dis->hwndItem != nullptr)
        {
        HWND hButton = dis->hwndItem;
        HWND hParent = GetParent(hButton);

        LONG_PTR style = GetWindowLongPtrW(hButton, GWL_STYLE);

        if (hParent == g_hDialog &&
            (style & BS_OWNERDRAW))
            {
                std::ostringstream ss;

                ss << "[WM_DRAWITEM_STATE_TEST] "
                << "button=" << hButton
                << " state_before=0x"
                << std::hex << dis->itemState
                << " rc=("
                << std::dec
                << dis->rcItem.left << ","
                << dis->rcItem.top << ")-("
                << dis->rcItem.right << ","
                << dis->rcItem.bottom << ")";

                Log(ss.str());

                // ------------------------------------------------------------
                // V22: проверяем UxTheme для owner-draw Button
                // ------------------------------------------------------------

                HTHEME hTheme = OpenThemeData(
                    dis->hwndItem,
                    L"Button"
                );

                std::ostringstream themeLog;

                themeLog << "[V22_THEME] "
                        << "button=" << dis->hwndItem
                        << " hTheme=" << hTheme;

                if (hTheme != nullptr)
                {
                    themeLog << " theme_open=YES";
                    CloseThemeData(hTheme);
                }
                else
                {
                    themeLog << " theme_open=NO";
                }

                Log(themeLog.str());

                COLORREF textBefore = GetTextColor(dis->hDC);
                COLORREF bkBefore   = GetBkColor(dis->hDC);

                HFONT fontBefore = reinterpret_cast<HFONT>(
                    GetCurrentObject(dis->hDC, OBJ_FONT)
                );

                HBRUSH brushBefore = reinterpret_cast<HBRUSH>(
                    GetCurrentObject(dis->hDC, OBJ_BRUSH)
                );

                HPEN penBefore = reinterpret_cast<HPEN>(
                    GetCurrentObject(dis->hDC, OBJ_PEN)
                );

                HBITMAP bitmapBefore = reinterpret_cast<HBITMAP>(
                    GetCurrentObject(dis->hDC, OBJ_BITMAP)
                );

                int bkModeBefore = GetBkMode(dis->hDC);

                LRESULT result = CallWindowProcW(
                    g_originalWndProc,
                    hwnd,
                    uMsg,
                    wParam,
                    lParam
                );

                HFONT fontAfter = reinterpret_cast<HFONT>(
                    GetCurrentObject(dis->hDC, OBJ_FONT)
                );

                HBRUSH brushAfter = reinterpret_cast<HBRUSH>(
                    GetCurrentObject(dis->hDC, OBJ_BRUSH)
                );

                HPEN penAfter = reinterpret_cast<HPEN>(
                    GetCurrentObject(dis->hDC, OBJ_PEN)
                );

                HBITMAP bitmapAfter = reinterpret_cast<HBITMAP>(
                    GetCurrentObject(dis->hDC, OBJ_BITMAP)
                );

                int bkModeAfter = GetBkMode(dis->hDC);

                COLORREF textAfter = GetTextColor(dis->hDC);
                COLORREF bkAfter   = GetBkColor(dis->hDC);

                std::ostringstream ss2;
                ss2 << "[WM_DRAWITEM_DC] "
                    << "button=" << dis->hwndItem
                    << " hdc=" << dis->hDC
                    << " textBefore=0x" << std::hex << textBefore
                    << " textAfter=0x" << textAfter
                    << " bkBefore=0x" << bkBefore
                    << " bkAfter=0x" << bkAfter
                    << " textBefore=" << textBefore
                    << " textAfter=" << textAfter
                    << " bkBefore=" << bkBefore
                    << " bkAfter=" << bkAfter

                    << " fontBefore=" << reinterpret_cast<uintptr_t>(fontBefore)
                    << " fontAfter=" << reinterpret_cast<uintptr_t>(fontAfter)

                    << " brushBefore=" << reinterpret_cast<uintptr_t>(brushBefore)
                    << " brushAfter=" << reinterpret_cast<uintptr_t>(brushAfter)

                    << " penBefore=" << reinterpret_cast<uintptr_t>(penBefore)
                    << " penAfter=" << reinterpret_cast<uintptr_t>(penAfter)

                    << " bitmapBefore=" << reinterpret_cast<uintptr_t>(bitmapBefore)
                    << " bitmapAfter=" << reinterpret_cast<uintptr_t>(bitmapAfter)

                    << " bkModeBefore=" << bkModeBefore
                    << " bkModeAfter=" << bkModeAfter;
                Log(ss2.str());

                return result;
            }
        }    
    }

    if (uMsg == WM_CTLCOLORBTN)
    {
        HWND hButton = reinterpret_cast<HWND>(lParam);

        if (hButton != nullptr &&
            GetParent(hButton) == g_hDialog)
        {
            Log("[WM_CTLCOLORBTN] owner-draw button");

            HDC hdc = reinterpret_cast<HDC>(wParam);

            SetBkColor(hdc, RGB(30, 30, 30));
            SetTextColor(hdc, RGB(220, 220, 220));

            std::ostringstream ss;
            ss << "[WM_CTLCOLORBTN] "
            << "button=" << hButton
            << " hdc=" << hdc;

            Log(ss.str());

            return reinterpret_cast<LRESULT>(g_hDarkBrush);
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

    if (InstallDrawThemeTextExHook())
    {
        Log("[V23] DrawThemeTextEx hook: SUCCESS");
    }
    else
    {
        Log("[V23] DrawThemeTextEx hook: FAILED");
    }

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
