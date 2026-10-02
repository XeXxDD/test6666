#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <fstream>
#include <sstream>
#include <uxtheme.h>
#include <vsstyle.h>
#include <vector>
#include <psapi.h>

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
static int g_v28Saved = 0;
static bool g_v29PixelTestDone = false;
static bool g_v31AfterAnalyzeTestDone = false;
static bool g_v33ModuleScanDone = false;

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
struct V27ButtonSnapshot
{
    HWND hwnd = nullptr;
    UINT state = 0;
    int width = 0;
    int height = 0;
};

static V27ButtonSnapshot g_v27Last{};

static bool IsSameV27Snapshot(
    HWND hwnd,
    UINT state,
    int width,
    int height
)
{
    return
        g_v27Last.hwnd == hwnd &&
        g_v27Last.state == state &&
        g_v27Last.width == width &&
        g_v27Last.height == height;
}
static void SaveButtonBitmap(
    HDC memDC,
    HBITMAP bitmap,
    int width,
    int height,
    HWND hwndButton,
    UINT state
)
{
    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    const DWORD dataSize =
        static_cast<DWORD>(width) *
        static_cast<DWORD>(height) *
        4;

    std::vector<BYTE> pixels(dataSize);

    int dibResult = GetDIBits(
        memDC,
        bitmap,
        0,
        height,
        pixels.data(),
        reinterpret_cast<BITMAPINFO*>(&bi),
        DIB_RGB_COLORS
    );

    std::ostringstream v32;

    v32 << "[V32] GETDIBITS"
        << " button=" << HwndToString(hwndButton)
        << " result=" << dibResult
        << " expected=" << height;

    if (dibResult > 0 && width >= 3 && height >= 3)
    {
        const size_t pixelOffset =
            (static_cast<size_t>(2) * static_cast<size_t>(width) + 2) * 4;

        const unsigned char b = pixels[pixelOffset + 0];
        const unsigned char g = pixels[pixelOffset + 1];
        const unsigned char r = pixels[pixelOffset + 2];

        COLORREF dibPixel = RGB(r, g, b);

        v32 << " pixel(2,2)=0x"
            << std::hex
            << static_cast<unsigned int>(dibPixel)
            << std::dec;
    }

    Log(v32.str());

    std::string fileName =
        "button_" +
        HwndToString(hwndButton) +
        "_state_" +
        std::to_string(state) +
        ".bmp";

    BITMAPFILEHEADER bfh{};
    bfh.bfType = 0x4D42;
    bfh.bfOffBits =
        sizeof(BITMAPFILEHEADER) +
        sizeof(BITMAPINFOHEADER);
    bfh.bfSize =
        bfh.bfOffBits + dataSize;

    std::ofstream file(
        fileName,
        std::ios::binary
    );

    if (!file)
    {
        Log("[V28] Cannot create BMP");
        return;
    }

    file.write(
        reinterpret_cast<const char*>(&bfh),
        sizeof(bfh)
    );

    file.write(
        reinterpret_cast<const char*>(&bi),
        sizeof(bi)
    );

    file.write(
        reinterpret_cast<const char*>(pixels.data()),
        dataSize
    );

    file.close();

    Log("[V28] Saved surface: " + fileName);
}

static void AnalyzeButtonSurfaceV27(
    HDC hdc,
    const RECT& rc,
    HWND hwndButton,
    UINT state
)
{
    if (hdc == nullptr)
        return;

    const int width = rc.right - rc.left;
    const int height = rc.bottom - rc.top;

    if (width <= 0 || height <= 0)
        return;

    if (IsSameV27Snapshot(
            hwndButton,
            state,
            width,
            height))
    {
        return;
    }

    g_v27Last.hwnd = hwndButton;
    g_v27Last.state = state;
    g_v27Last.width = width;
    g_v27Last.height = height;

    HDC memDC = CreateCompatibleDC(hdc);

    if (memDC == nullptr)
    {
        Log("[V27] CreateCompatibleDC FAILED");
        return;
    }

    HBITMAP bitmap = CreateCompatibleBitmap(
        hdc,
        width,
        height
    );

    if (bitmap == nullptr)
    {
        Log("[V27] CreateCompatibleBitmap FAILED");
        DeleteDC(memDC);
        return;
    }

    HGDIOBJ oldBitmap = SelectObject(
        memDC,
        bitmap
    );

    BOOL copied = BitBlt(
        memDC,
        0,
        0,
        width,
        height,
        hdc,
        rc.left,
        rc.top,
        SRCCOPY
    );

    if (copied)
    {
        // ============================================================
        // V29: TEST POST-PROCESSING
        // Capture -> modify 3x3 pixels -> copy back to original HDC
        // ============================================================
        if (!g_v29PixelTestDone && width >= 10 && height >= 10)
        {
            g_v29PixelTestDone = true;

            const int testX = 2;
            const int testY = 2;

            COLORREF before = GetPixel(memDC, testX, testY);

            // 3x3 ярко-жёлтый маркер.
            // Это только диагностический тест.
            for (int y = 0; y < 3; ++y)
            {
                for (int x = 0; x < 3; ++x)
                {
                    SetPixel(
                        memDC,
                        testX + x,
                        testY + y,
                        RGB(255, 255, 0)
                    );
                }
            }

            std::ostringstream v29;

            v29 << "[V29] POSTPROCESS TEST"
                << " button=" << HwndToString(hwndButton)
                << " size=" << width << "x" << height
                << " pixel=(" << testX << "," << testY << ")"
                << " before=0x"
                << std::hex << static_cast<unsigned int>(before)
                << std::dec;

            Log(v29.str());

            BOOL copiedBack = BitBlt(
                hdc,
                rc.left,
                rc.top,
                width,
                height,
                memDC,
                0,
                0,
                SRCCOPY
            );

            COLORREF after = GetPixel(
                hdc,
                rc.left + testX,
                rc.top + testY
            );

            std::ostringstream v30;

            v30 << "[V30] COPY BACK: "
                << (copiedBack ? "YES" : "NO")
                << " after=0x"
                << std::hex
                << static_cast<unsigned int>(after)
                << std::dec;

            Log(v30.str());
        }
        if (g_v28Saved < 10)
        {
            SaveButtonBitmap(
                memDC,
                bitmap,
                width,
                height,
                hwndButton,
                state
            );

            ++g_v28Saved;
        }
    }

    if (!copied)
    {
        Log("[V27] BitBlt FAILED");

        SelectObject(memDC, oldBitmap);
        DeleteObject(bitmap);
        DeleteDC(memDC);
        return;
    }

    int nonBackground = 0;

    int minR = 255;
    int minG = 255;
    int minB = 255;

    int maxR = 0;
    int maxG = 0;
    int maxB = 0;

    int brightPixels = 0;

    const COLORREF background = RGB(30, 30, 30);

    for (int y = 0; y < height; ++y)
    {
        for (int x = 0; x < width; ++x)
        {
            COLORREF c = GetPixel(
                memDC,
                x,
                y
            );

            if (c == CLR_INVALID)
                continue;

            const int r = GetRValue(c);
            const int g = GetGValue(c);
            const int b = GetBValue(c);

            if (c != background)
                ++nonBackground;

            minR = min(minR, r);
            minG = min(minG, g);
            minB = min(minB, b);

            maxR = max(maxR, r);
            maxG = max(maxG, g);
            maxB = max(maxB, b);

            if (r >= 150 &&
                g >= 150 &&
                b >= 150)
            {
                ++brightPixels;
            }
        }
    }

    std::ostringstream ss;

    ss << "[V27] button="
       << HwndToString(hwndButton)
       << " size="
       << width
       << "x"
       << height
       << " state=0x"
       << std::hex
       << state
       << std::dec
       << " theme=";

    HTHEME hTheme = OpenThemeData(
        hwndButton,
        L"Button"
    );

    if (hTheme != nullptr)
    {
        ss << "YES";
        CloseThemeData(hTheme);
    }
    else
    {
        ss << "NO";
    }

    Log(ss.str());

    ss.str("");
    ss.clear();

    ss << "[V27] surface"
       << " bg=0x1e1e1e"
       << " nonBG="
       << nonBackground
       << " bright="
       << brightPixels
       << " min=("
       << minR << ","
       << minG << ","
       << minB << ")"
       << " max=("
       << maxR << ","
       << maxG << ","
       << maxB << ")";

    Log(ss.str());

    SelectObject(
        memDC,
        oldBitmap
    );

    DeleteObject(bitmap);
    DeleteDC(memDC);
}

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
            dis->hwndItem != nullptr &&
            GetParent(dis->hwndItem) == g_hDialog)
        {

        LRESULT nativeResult =
            CallWindowProcW(
                g_originalWndProc,
                hwnd,
                uMsg,
                wParam,
                lParam
            );

        // ============================================================
        // V38: TEST AFTER NATIVE CALL
        // ============================================================
        if (!g_v33ModuleScanDone)
        {
            g_v33ModuleScanDone = true;

            Log("[V38] AFTER CallWindowProcW");
        }
        
            return nativeResult;
        }
    }    
    

    if (uMsg == WM_CTLCOLORBTN)
    {
        HWND hButton =
        reinterpret_cast<HWND>(lParam);

    if (hButton != nullptr &&
        GetParent(hButton) == g_hDialog)
        {
            HDC hdc =
                reinterpret_cast<HDC>(wParam);

            SetBkColor(
                hdc,
                RGB(30, 30, 30)
            );

            SetTextColor(
                hdc,
                RGB(220, 220, 220)
            );

            return reinterpret_cast<LRESULT>(
                g_hDarkBrush
            );
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
