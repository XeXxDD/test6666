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
#include <detours.h>
#include <intrin.h>
#include <iomanip>
#include <tlhelp32.h>
#include <winnt.h>

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
static bool g_v31AfterAnalyzeTestDone = false;
static bool g_v33ModuleScanDone = false;
static unsigned long long g_drawSeq = 0;
static HDC g_lastDrawHDC = nullptr;
static bool g_v85FunctionDumpDone = false;

void Log(const std::string& msg);

// ========================= V62 =========================

typedef BOOL (WINAPI* ExtTextOutW_t)(
    HDC,
    int,
    int,
    UINT,
    const RECT*,
    LPCWSTR,
    UINT,
    const INT*
);

typedef COLORREF (WINAPI* SetTextColor_t)(
    HDC hdc,
    COLORREF color
);

static SetTextColor_t g_realSetTextColor = SetTextColor;
static ExtTextOutW_t g_realExtTextOutW = ExtTextOutW;



static std::string HexDumpV66(const unsigned char* data, size_t count)
{
    std::ostringstream ss;

    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
            ss << ' ';

        ss << std::uppercase
           << std::hex
           << std::setw(2)
           << std::setfill('0')
           << static_cast<unsigned int>(data[i]);
    }

    return ss.str();
}

static void DumpCallerBytesV66(void* caller)
{
    if (caller == nullptr)
        return;

    unsigned char* p = reinterpret_cast<unsigned char*>(caller);

    // _ReturnAddress() указывает сразу ПОСЛЕ CALL SetTextColor.
    // Поэтому смотрим 16 байт назад и 32 байта вперёд.
    const size_t before = 512;
    const size_t after = 128;

    unsigned char bytesBefore[before] = {};
    unsigned char bytesAfter[after] = {};

    memcpy(bytesBefore, p - before, before);
    memcpy(bytesAfter, p, after);

    std::ostringstream ss;

    ss << "[V66] HEX caller=" << caller
        << " before[-" << before << "..-1]="
        << HexDumpV66(bytesBefore, before)
        << " after[0.." << (after - 1) << "]=" // Выведет: after[0..95]=
        << HexDumpV66(bytesAfter, after);

    Log(ss.str());
}

// ========================= V79 =========================
// Проверяем найденную внутреннюю функцию SC2 без установки hook.
//
// SC2Editor + 0x1F4ED34
// ========================================================

static void CheckInternalColorFuncV79(void* referenceAddress)
{
    if (referenceAddress == nullptr)
    {
        Log("[V79] referenceAddress == nullptr.");
        return;
    }

    HMODULE hModule = nullptr;

    if (!GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(referenceAddress),
        &hModule))
    {
        Log("[V79] GetModuleHandleExW failed.");
        return;
    }

    MODULEINFO moduleInfo{};

    if (!GetModuleInformation(
        GetCurrentProcess(),
        hModule,
        &moduleInfo,
        sizeof(moduleInfo)))
    {
        Log("[V79] GetModuleInformation failed.");
        return;
    }

    ULONG_PTR base =
        reinterpret_cast<ULONG_PTR>(
            moduleInfo.lpBaseOfDll
        );

    ULONG_PTR target = base + 0x1F4ED30;

    std::ostringstream ss;

    ss << "[V79] INTERNAL target="
       << reinterpret_cast<void*>(target)
       << " rva=0x1F4ED34";

    Log(ss.str());

    unsigned char bytes[32] = {};

    memcpy(
        bytes,
        reinterpret_cast<const void*>(target),
        sizeof(bytes)
    );

    std::ostringstream dump;

    dump << "[V79] ENTRY BYTES:";

    for (int i = 0; i < 32; ++i)
    {
        dump << ' '
             << std::uppercase
             << std::hex
             << std::setw(2)
             << std::setfill('0')
             << static_cast<unsigned int>(bytes[i]);
    }

    Log(dump.str());

    bool expected =
        bytes[0] == 0x40 &&
        bytes[1] == 0x55 &&
        bytes[2] == 0x53 &&
        bytes[3] == 0x56 &&
        bytes[4] == 0x57 &&
        bytes[5] == 0x41 &&
        bytes[6] == 0x54 &&
        bytes[7] == 0x41 &&
        bytes[8] == 0x55 &&
        bytes[9] == 0x41 &&
        bytes[10] == 0x56 &&
        bytes[11] == 0x41 &&
        bytes[12] == 0x57;

    if (expected)
    {
        Log("[V79] Expected function prologue confirmed.");
    }
    else
    {
        Log("[V79] WARNING: function prologue differs from V77.");
    }

    if (bytes[0] == 0xE9 ||
        bytes[0] == 0xE8 ||
        bytes[0] == 0xCC)
    {
        Log("[V79] WARNING: first byte looks like JMP/CALL/INT3 hook.");
    }
    else
    {
        Log("[V79] First byte does not look like JMP/CALL/INT3 hook.");
    }
}

// ========================= V79 END =========================

// ========================= V81 =========================
// Определяем настоящий entry point функции, содержащей
// доказанный SetTextColor caller.
//
// caller = SC2Editor + 0x1F4EDC8
// ========================================================

static void CheckFunctionEntryV81(void* caller)
{
    if (caller == nullptr)
    {
        Log("[V81] caller == nullptr.");
        return;
    }

    DWORD64 controlPc =
        reinterpret_cast<DWORD64>(caller);

    DWORD64 imageBase = 0;

    PRUNTIME_FUNCTION rf =
        RtlLookupFunctionEntry(
            controlPc,
            &imageBase,
            nullptr
        );

    if (rf == nullptr)
    {
        Log("[V81] RtlLookupFunctionEntry returned NULL.");
        return;
    }

    DWORD64 functionBegin =
        imageBase + rf->BeginAddress;

    DWORD64 functionEnd =
        imageBase + rf->EndAddress;

    std::ostringstream ss;

    ss << "[V81] FUNCTION"
       << " caller=" << reinterpret_cast<void*>(controlPc)
       << " imageBase=" << reinterpret_cast<void*>(imageBase)
       << " BeginAddress=0x"
       << std::hex
       << rf->BeginAddress
       << " EndAddress=0x"
       << rf->EndAddress
       << " entry=" << reinterpret_cast<void*>(functionBegin)
       << " end=" << reinterpret_cast<void*>(functionEnd);

    Log(ss.str());

    DWORD64 entryRva =
        functionBegin - imageBase;

    std::ostringstream ss2;

    ss2 << "[V81] ENTRY_RVA=0x"
        << std::hex
        << entryRva;

    Log(ss2.str());
}

// ========================= V81 END =========================

// ========================= V88 =========================
//
// Manual x64 inline hook.
//
// Target:
//   SC2Editor_x64.exe + 0x1F4ED30
//
// Original prologue:
//
//   40 55
//   53
//   56
//   57
//   41 54
//   41 55
//   41 56
//   41 57
//
// First 13 bytes are copied intact to trampoline.
// Target is patched with:
//
//   48 B8 <uint64 address>
//   FF E0
//
// which is a 12-byte absolute JMP.
//
// =========================

using InternalColorFuncV88 =
    void* (__fastcall*)(
        void* rcx,
        void* rdx,
        void* arg3,
        void* arg4
    );

static InternalColorFuncV88 g_OriginalInternalColorFuncV88 = nullptr;

static void* g_V88Target = nullptr;
static void* g_V88Trampoline = nullptr;

static constexpr SIZE_T V88_OVERWRITE_SIZE = 13;
static constexpr SIZE_T V88_JUMP_SIZE = 12;


// ------------------------------------------------------------
// V88: write absolute x64 jump
// ------------------------------------------------------------

static bool WriteAbsoluteJumpV88(
    void* source,
    void* destination
)
{
    if (source == nullptr || destination == nullptr)
        return false;

    unsigned char jump[V88_JUMP_SIZE] =
    {
        0x48, 0xB8,                         // mov rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0,            // address
        0xFF, 0xE0                          // jmp rax
    };

    const ULONG_PTR address =
        reinterpret_cast<ULONG_PTR>(destination);

    memcpy(
        &jump[2],
        &address,
        sizeof(address)
    );

    std::ostringstream vp;

    vp << "[V89] VirtualProtect"
    << " source=" << source
    << " size=0x"
    << std::hex
    << V88_OVERWRITE_SIZE
    << " process="
    << GetCurrentProcess()
    << " target="
    << g_V88Target;

    Log(vp.str());

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t sourceAddress = reinterpret_cast<uintptr_t>(source);
    uintptr_t pageBase =
        sourceAddress & ~(static_cast<uintptr_t>(si.dwPageSize) - 1);

    SIZE_T regionSize = si.dwPageSize;

    DWORD oldProtect = 0;

    std::ostringstream pg;
    pg << "[V90] PAGE"
    << " source=" << source
    << " pageBase=" << reinterpret_cast<void*>(pageBase)
    << " pageSize=0x" << std::hex << regionSize;

    Log(pg.str());

    MEMORY_BASIC_INFORMATION mbi{};

    SIZE_T q =
        VirtualQuery(
            source,
            &mbi,
            sizeof(mbi)
        );

    std::ostringstream vm;

    vm << "[V89] VirtualQuery"
    << " result=0x"
    << std::hex
    << q
    << " BaseAddress=" << mbi.BaseAddress
    << " AllocationBase=" << mbi.AllocationBase
    << " RegionSize=0x" << mbi.RegionSize
    << " Protect=0x" << mbi.Protect
    << " AllocationProtect=0x"
    << mbi.AllocationProtect
    << " State=0x"
    << mbi.State
    << " Type=0x"
    << mbi.Type;

    Log(vm.str());

    BOOL vpResult = VirtualProtect(
        reinterpret_cast<void*>(pageBase),
        regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    std::ostringstream result;

    result << "[V89] VirtualProtect result="
        << vpResult
        << " error="
        << GetLastError()
        << " oldProtect=0x"
        << std::hex
        << oldProtect;

    Log(result.str());

    if (!vpResult)
        return false;

    memcpy(
        source,
        jump,
        sizeof(jump)
    );

    FlushInstructionCache(
        GetCurrentProcess(),
        source,
        V88_OVERWRITE_SIZE
    );

    DWORD dummy = 0;

    VirtualProtect(
        source,
        V88_OVERWRITE_SIZE,
        oldProtect,
        &dummy
    );

    return true;
}


// ------------------------------------------------------------
// V88: actual handler
// ------------------------------------------------------------

static void* __fastcall HookInternalColorFuncV88(
    void* rcx,
    void* rdx,
    void* arg3,
    void* arg4)
{
    DWORD flags = 0;

    if (rdx != nullptr)
    {
        flags =
            *reinterpret_cast<DWORD*>(
                reinterpret_cast<BYTE*>(rdx) + 0x18
            );
    }

    std::ostringstream ss;

    ss << "[V88] INTERNAL_ENTRY"
       << " RCX=" << rcx
       << " RDX=" << rdx
       << " ARG3=" << arg3
       << " ARG4=" << arg4
       << " FLAGS18=0x"
       << std::hex
       << std::uppercase
       << flags;

    Log(ss.str());


    // --------------------------------------------------------
    // AGGRESSIVE TEST
    //
    // The original function explicitly tests bit 2:
    //
    //   mov ecx,[rdx+18]
    //   shr ecx,2
    //   test cl,1
    //
    // Therefore bit 0x4 is the first thing we test.
    //
    // DO NOT RESTORE IT.
    // --------------------------------------------------------

    if (rdx != nullptr &&
        (flags & 0x4u) != 0)
    {
        DWORD modified =
            flags & ~0x4u;

        *reinterpret_cast<DWORD*>(
            reinterpret_cast<BYTE*>(rdx) + 0x18
        ) = modified;

        std::ostringstream test;

        test << "[V88] *** MODIFIED [RDX+18] ***"
             << " RDX=" << rdx
             << " old=0x"
             << std::hex
             << std::uppercase
             << flags
             << " new=0x"
             << modified
             << " bit2 CLEARED";

        Log(test.str());
    }


    // --------------------------------------------------------
    // Continue through the original function.
    // --------------------------------------------------------

    InternalColorFuncV88 original =
        reinterpret_cast<InternalColorFuncV88>(
            g_V88Trampoline
        );

    return original(
        rcx,
        rdx,
        arg3,
        arg4
    );
}


// ------------------------------------------------------------
// V88: install manual inline hook
// ------------------------------------------------------------

static bool InstallInternalColorHookV88()
{
    if (g_V88Target != nullptr)
    {
        Log("[V88] Hook already installed.");
        return true;
    }

    HMODULE hSc2 =
        GetModuleHandleW(
            L"SC2Editor_x64.exe"
        );

    if (hSc2 == nullptr)
    {
        Log(
            "[V88] SC2Editor_x64.exe module not found."
        );

        return false;
    }

    uintptr_t base =
        reinterpret_cast<uintptr_t>(hSc2);

    unsigned char* target =
        reinterpret_cast<unsigned char*>(
            base + 0x1F4ED30
        );


    // --------------------------------------------------------
    // Verify the known function prologue before touching it.
    // --------------------------------------------------------

    const unsigned char expected[V88_OVERWRITE_SIZE] =
    {
        0x40, 0x55,
        0x53,
        0x56,
        0x57,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57
    };

    if (memcmp(
        target,
        expected,
        V88_OVERWRITE_SIZE) != 0)
    {
        Log(
            "[V88] ERROR: target prologue does not match expected bytes."
        );

        std::ostringstream ss;

        ss << "[V88] TARGET BYTES:";

        for (SIZE_T i = 0; i < 32; ++i)
        {
            ss << ' '
               << std::uppercase
               << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(
                    target[i]
               );
        }

        Log(ss.str());

        return false;
    }


    std::ostringstream targetLog;

    targetLog
        << "[V88] TARGET="
        << static_cast<void*>(target)
        << " RVA=0x1F4ED30";

    Log(targetLog.str());


    // --------------------------------------------------------
    // Allocate executable trampoline.
    // --------------------------------------------------------

    unsigned char* trampoline =
        reinterpret_cast<unsigned char*>(
            VirtualAlloc(
                nullptr,
                64,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
        );

    if (trampoline == nullptr)
    {
        std::ostringstream ss;

        ss << "[V88] VirtualAlloc trampoline failed. error="
           << GetLastError();

        Log(ss.str());

        return false;
    }


    // --------------------------------------------------------
    // Copy complete original instructions.
    //
    // 13 bytes = complete prologue through:
    //
    //   41 57
    // --------------------------------------------------------

    memcpy(
        trampoline,
        target,
        V88_OVERWRITE_SIZE
    );


    // --------------------------------------------------------
    // Append absolute jump:
    //
    //   mov rax, target + 13
    //   jmp rax
    // --------------------------------------------------------

    unsigned char* trampolineJump =
        trampoline + V88_OVERWRITE_SIZE;

    const ULONG_PTR returnAddress =
        reinterpret_cast<ULONG_PTR>(
            target + V88_OVERWRITE_SIZE
        );

    trampolineJump[0] = 0x48;
    trampolineJump[1] = 0xB8;

    memcpy(
        &trampolineJump[2],
        &returnAddress,
        sizeof(returnAddress)
    );

    trampolineJump[10] = 0xFF;
    trampolineJump[11] = 0xE0;


    FlushInstructionCache(
        GetCurrentProcess(),
        trampoline,
        64
    );


    // --------------------------------------------------------
    // Install JMP target -> our handler.
    // --------------------------------------------------------

    if (!WriteAbsoluteJumpV88(
        target,
        reinterpret_cast<void*>(
            HookInternalColorFuncV88
        )))
    {
        VirtualFree(
            trampoline,
            0,
            MEM_RELEASE
        );

        return false;
    }


    g_V88Target =
        reinterpret_cast<void*>(target);

    g_V88Trampoline =
        reinterpret_cast<void*>(trampoline);

    g_OriginalInternalColorFuncV88 =
        reinterpret_cast<InternalColorFuncV88>(
            trampoline
        );


    std::ostringstream ss;

    ss << "[V88] INLINE HOOK INSTALLED"
       << " target="
       << g_V88Target
       << " trampoline="
       << g_V88Trampoline
       << " handler="
       << reinterpret_cast<void*>(
            HookInternalColorFuncV88
          )
       << " return="
       << reinterpret_cast<void*>(
            target + V88_OVERWRITE_SIZE
          );

    Log(ss.str());

    return true;
}

// ========================= V88 END =========================


// ============================================================
// V77 — dump code around a specific RVA inside the caller's module
// ============================================================
static void DumpCodeAtRvaV77(
    void* referenceAddress,
    ULONG_PTR targetRva,
    SIZE_T before,
    SIZE_T after)
{
    HMODULE hModule = nullptr;

    if (!GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(referenceAddress),
        &hModule))
    {
        Log("[V77] GetModuleHandleExW failed");
        return;
    }

    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(
        GetCurrentProcess(),
        hModule,
        &moduleInfo,
        sizeof(moduleInfo)))
    {
        Log("[V77] GetModuleInformation failed");
        return;
    }

    ULONG_PTR base =
        reinterpret_cast<ULONG_PTR>(moduleInfo.lpBaseOfDll);

    SIZE_T moduleSize = moduleInfo.SizeOfImage;

    if (targetRva >= moduleSize)
    {
        std::ostringstream ss;
        ss << "[V77] target RVA outside module: rva=0x"
           << std::hex << targetRva
           << " moduleSize=0x" << moduleSize;

        Log(ss.str());
        return;
    }

    if (before > targetRva)
        before = static_cast<SIZE_T>(targetRva);

    SIZE_T remaining =
        moduleSize - static_cast<SIZE_T>(targetRva);

    if (after > remaining)
        after = remaining;

    const unsigned char* target =
        reinterpret_cast<const unsigned char*>(
            base + targetRva);

    std::ostringstream header;

    header << "[V77] TARGET"
           << " moduleBase=" << reinterpret_cast<void*>(base)
           << " rva=0x" << std::hex << targetRva
           << " address=" << reinterpret_cast<const void*>(target)
           << " before=" << std::dec << before
           << " after=" << after;

    Log(header.str());

    // Dump before the target in 16-byte lines.
    for (SIZE_T offset = 0; offset < before; offset += 16)
    {
        SIZE_T lineSize =
            (before - offset < 16)
                ? (before - offset)
                : 16;

        const unsigned char* p =
            target - before + offset;

        std::ostringstream ss;

        LONG_PTR relative =
            -static_cast<LONG_PTR>(before - offset);

        ss << "[V77] "
           << (relative < 0 ? "-" : "+")
           << "0x"
           << std::hex
           << static_cast<ULONG_PTR>(
                  relative < 0 ? -relative : relative)
           << ":";

        for (SIZE_T i = 0; i < lineSize; ++i)
        {
            ss << ' '
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(p[i]);
        }

        Log(ss.str());
    }

    // Dump target + after in 16-byte lines.
    for (SIZE_T offset = 0; offset < after; offset += 16)
    {
        SIZE_T lineSize =
            (after - offset < 16)
                ? (after - offset)
                : 16;

        const unsigned char* p =
            target + offset;

        std::ostringstream ss;

        ss << "[V77] +0x"
           << std::hex
           << std::setw(4)
           << std::setfill('0')
           << offset
           << ":";

        for (SIZE_T i = 0; i < lineSize; ++i)
        {
            ss << ' '
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(p[i]);
        }

        Log(ss.str());
    }
}
// ========================= V67 =========================
// Читаем только уже доказанный CALL-site:
//
// SC2Editor + 0x1F4EDC8
//
// На входе сюда caller = адрес СРАЗУ ПОСЛЕ CALL.
// Сам CALL имеет длину 6 байт:
// FF 15 xx xx xx xx
//
// Поэтому:
// callSite = caller - 6
//
// Затем вычисляем реальный target:
// target = (callSite + 6) + disp32
// =========================

static void AnalyzeCallSiteV67(void* caller)
{
    if (caller == nullptr)
        return;

    unsigned char* returnAddress =
        reinterpret_cast<unsigned char*>(caller);

    unsigned char* callSite =
        returnAddress - 6;

    unsigned char bytes[6] = {};

    memcpy(
        bytes,
        callSite,
        sizeof(bytes)
    );

    //
    // Проверяем, что это именно:
    //
    // FF 15 xx xx xx xx
    //
    if (bytes[0] != 0xFF ||
        bytes[1] != 0x15)
    {
        return;
    }

    INT32 displacement = 0;

    memcpy(
        &displacement,
        &bytes[2],
        sizeof(displacement)
    );

    unsigned char* nextInstruction =
        callSite + 6;

    unsigned char* targetAddress =
        nextInstruction + displacement;

    std::ostringstream ss;

    ss << "[V67] CALL_SITE"
       << " caller=" << caller
       << " callSite=" << static_cast<void*>(callSite)
       << " bytes="
       << std::uppercase
       << std::hex
       << std::setw(2)
       << std::setfill('0')
       << static_cast<unsigned int>(bytes[0])
       << " "
       << std::setw(2)
       << static_cast<unsigned int>(bytes[1])
       << " "
       << std::setw(2)
       << static_cast<unsigned int>(bytes[2])
       << " "
       << std::setw(2)
       << static_cast<unsigned int>(bytes[3])
       << " "
       << std::setw(2)
       << static_cast<unsigned int>(bytes[4])
       << " "
       << std::setw(2)
       << static_cast<unsigned int>(bytes[5])
       << std::dec
       << " displacement="
       << displacement
       << " target="
       << static_cast<void*>(targetAddress);

    Log(ss.str());
}
// ========================= V67 END =========================

// ========================= V67b-2 =========================

static void AnalyzeIATTargetV67b2(void* caller)
{
    if (caller == nullptr)
        return;

    unsigned char* returnAddress =
        reinterpret_cast<unsigned char*>(caller);

    unsigned char* callSite =
        returnAddress - 6;

    unsigned char bytes[6] = {};

    memcpy(
        bytes,
        callSite,
        sizeof(bytes)
    );

    if (bytes[0] != 0xFF ||
        bytes[1] != 0x15)
    {
        return;
    }

    INT32 displacement = 0;

    memcpy(
        &displacement,
        &bytes[2],
        sizeof(displacement)
    );

    unsigned char* nextInstruction =
        callSite + 6;

    unsigned char* iatSlot =
        nextInstruction + displacement;

    ULONG_PTR actualTarget = 0;

    unsigned char iatBytes[8] = {};

    memcpy(
        iatBytes,
        iatSlot,
        sizeof(iatBytes)
    );

    memcpy(
        &actualTarget,
        iatBytes,
        sizeof(actualTarget)
    );

    ULONG_PTR detoursTarget =
        reinterpret_cast<ULONG_PTR>(
            g_realSetTextColor
    );

    MEMORY_BASIC_INFORMATION mbi{};

    SIZE_T queryResult = VirtualQuery(
        reinterpret_cast<LPCVOID>(iatSlot),
        &mbi,
        sizeof(mbi)
    );

    std::ostringstream ssMem;

    ssMem << "[V70] IAT_MEMORY"
          << " address="
          << static_cast<void*>(iatSlot)
          << " queryResult="
          << queryResult;

    if (queryResult == sizeof(mbi))
    {
        ssMem << " allocationBase="
              << mbi.AllocationBase
              << " baseAddress="
              << mbi.BaseAddress
              << " regionSize="
              << std::hex
              << mbi.RegionSize
              << std::dec
              << " state=0x"
              << std::hex
              << mbi.State
              << " protect=0x"
              << mbi.Protect
              << " type=0x"
              << mbi.Type
              << std::dec;
    }

    Log(ssMem.str());

    std::ostringstream ss;

    ss << "[V69] IAT"
    << " callSite="
    << static_cast<void*>(callSite)
    << " iatSlot="
    << static_cast<void*>(iatSlot)
    << " bytes="
    << std::uppercase
    << std::hex
    << std::setw(2)
    << std::setfill('0')
    << static_cast<unsigned int>(iatBytes[0])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[1])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[2])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[3])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[4])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[5])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[6])
    << " "
    << std::setw(2)
    << static_cast<unsigned int>(iatBytes[7])
    << std::dec
    << " actualTarget="
    << reinterpret_cast<void*>(actualTarget)
    << " g_realSetTextColor="
    << reinterpret_cast<void*>(detoursTarget);

    Log(ss.str());
}

// ========================= V67b-2 END =========================

static std::string GetCallerModuleInfoV65(void* address)
{
    HMODULE hModule = nullptr;

    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &hModule))
    {
        return "module=<unknown>";
    }

    MODULEINFO moduleInfo{};
    if (!GetModuleInformation(
            GetCurrentProcess(),
            hModule,
            &moduleInfo,
            sizeof(moduleInfo)))
    {
        return "module=<unknown>";
    }

    char modulePath[MAX_PATH] = {};
    GetModuleFileNameA(
        hModule,
        modulePath,
        sizeof(modulePath)
    );

    std::ostringstream ss;

    ss << "module=" << modulePath
       << " base=" << hModule
       << " offset=0x"
       << std::hex
       << (
           reinterpret_cast<ULONG_PTR>(address) -
           reinterpret_cast<ULONG_PTR>(moduleInfo.lpBaseOfDll)
       )
       << std::dec;

    return ss.str();
}

static COLORREF WINAPI HookSetTextColor(
    HDC hdc,
    COLORREF color,
    ULONG_PTR arg3,
    ULONG_PTR arg4
)
{        
    HWND fg = GetForegroundWindow();

    DWORD fgPid = 0;
    if (fg)
        GetWindowThreadProcessId(fg, &fgPid);

    std::ostringstream ssAll;

    ssAll << "[V74] SetTextColor"
      << " hDC=" << reinterpret_cast<void*>(hdc)
      << " color=0x"
      << std::hex
      << static_cast<unsigned int>(color)
      << " foreground="
      << reinterpret_cast<void*>(fg)
        << " fgPID="
        << std::dec
        << fgPid
        << " TID="
        << GetCurrentThreadId();

        Log(ssAll.str());
        
    if (hdc != nullptr)
    {
        void* caller = _ReturnAddress();

// ========================= V75 RDI TEST =========================
HMODULE hModuleV75 = nullptr;

if (GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(caller),
        &hModuleV75))
{
    MODULEINFO moduleInfoV75{};

    if (GetModuleInformation(
            GetCurrentProcess(),
            hModuleV75,
            &moduleInfoV75,
            sizeof(moduleInfoV75)))
    {
        ULONG_PTR baseV75 =
            reinterpret_cast<ULONG_PTR>(
                moduleInfoV75.lpBaseOfDll
            );

        ULONG_PTR callerAddrV75 =
            reinterpret_cast<ULONG_PTR>(caller);

        ULONG_PTR offsetV75 =
            callerAddrV75 - baseV75;

        if (offsetV75 == 0x1F4EDC8 &&
            (color == 0xA000 ||
             color == 0x804040))
        {
            std::ostringstream ssV75;

            ssV75 << "[V75] ARGS"
                << " color=0x"
                << std::hex
                << static_cast<unsigned int>(color)
                << " arg3=0x"
                << static_cast<ULONG_PTR>(arg3)
                << " arg4=0x"
                << static_cast<ULONG_PTR>(arg4);

            Log(ssV75.str());

            if (!g_v85FunctionDumpDone)
            {
                DumpCodeAtRvaV77(
                    caller,
                    0x1F4ED30,
                    0,
                    0x337
                );

                g_v85FunctionDumpDone = true;
            }

            CheckFunctionEntryV81(caller);
        }
    }
}
// ========================= V75 RDI TEST END =========================

// ========================= V67  =========================
        // анализируем только тот CALL-site,
        // который уже доказан V65/V66.
        //
        HMODULE hModuleV67 = nullptr;

        if (GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(caller),
                &hModuleV67))
        {
            MODULEINFO moduleInfoV67{};

            if (GetModuleInformation(
                    GetCurrentProcess(),
                    hModuleV67,
                    &moduleInfoV67,
                    sizeof(moduleInfoV67)))
            {
                const ULONG_PTR baseV67 =
                    reinterpret_cast<ULONG_PTR>(
                        moduleInfoV67.lpBaseOfDll
                    );

                const ULONG_PTR callerAddrV67 =
                    reinterpret_cast<ULONG_PTR>(caller);

                const ULONG_PTR offsetV67 =
                    callerAddrV67 - baseV67;

                //
                // Только наш доказанный call-site.
                //
                if (offsetV67 == 0x1F4EDC8 &&
                    (color == 0xA000 ||
                     color == 0x804040))
                {
                    AnalyzeCallSiteV67(caller);
                    AnalyzeIATTargetV67b2(caller);
                }
            }
        }
// ========================= V67 END =========================

        HMODULE hModule = nullptr;

        if (GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(caller),
                &hModule))
        {
            MODULEINFO moduleInfo{};

            if (GetModuleInformation(
                    GetCurrentProcess(),
                    hModule,
                    &moduleInfo,
                    sizeof(moduleInfo)))
            {
                const ULONG_PTR base =
                    reinterpret_cast<ULONG_PTR>(moduleInfo.lpBaseOfDll);

                const ULONG_PTR addr =
                    reinterpret_cast<ULONG_PTR>(caller);

                const ULONG_PTR offset =
                    addr - base;

                //
                // ЖЁСТКИЙ ФИЛЬТР V66:
                //
                // Только SC2Editor + 0x1F4EDC8
                //
                if (offset == 0x1F4EDC8)
                {
                    //
                    // И дополнительно только semantic colors,
                    // которые мы уже видели у Variable/Value.
                    //
                    if (color == 0xA000 || color == 0x804040)
                    {
                        DumpCallerBytesV66(caller);
                    }
                }
            }
        }
    }

    return g_realSetTextColor(hdc, color);
}

static BOOL WINAPI HookExtTextOutW(
    HDC hdc,
    int x,
    int y,
    UINT options,
    const RECT* lprc,
    LPCWSTR lpString,
    UINT c,
    const INT* lpDx
)
{
    if (hdc != nullptr && lpString != nullptr)
    {
        std::ostringstream ss;

        ss << "[V62] ExtTextOutW"
        << " hDC=" << hdc
        << " count=" << c
        << " color=0x"
        << std::hex
        << static_cast<unsigned int>(GetTextColor(hdc))
        << std::dec;

        Log(ss.str());
    }

    return g_realExtTextOutW(
        hdc,
        x,
        y,
        options,
        lprc,
        lpString,
        c,
        lpDx
    );
}
// ========================= V62 END =========================


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



static BOOL CALLBACK V55_EnumPropProc(
    HWND hwnd,
    LPWSTR lpszString,
    HANDLE hData,
    ULONG_PTR lParam)
{
    std::ostringstream ss;

    ss << "[V55] PROP hwnd=" << HwndToString(hwnd);

    if (HIWORD(reinterpret_cast<ULONG_PTR>(lpszString)) == 0)
    {
        ATOM atom = static_cast<ATOM>(
            LOWORD(reinterpret_cast<ULONG_PTR>(lpszString))
        );

        WCHAR atomName[256] = {};

        UINT atomNameLen = GlobalGetAtomNameW(
            atom,
            atomName,
            static_cast<int>(std::size(atomName))
        );

        ss << " name=ATOM:"
        << atom;

        if (atomNameLen > 0)
        {
            ss << " atomName=\"";

            int len = WideCharToMultiByte(
                CP_UTF8,
                0,
                atomName,
                atomNameLen,
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (len > 0)
            {
                std::string name;
                name.resize(len);

                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    atomName,
                    atomNameLen,
                    &name[0],
                    len,
                    nullptr,
                    nullptr
                );

                ss << name;
            }

            ss << "\"";
        }
        else
        {
            ss << " atomName=<not found>";
        }
    }
    else
    {
        int len = WideCharToMultiByte(
            CP_UTF8,
            0,
            lpszString,
            -1,
            nullptr,
            0,
            nullptr,
            nullptr
        );

        std::string name;

        if (len > 0)
        {
            name.resize(len);

            WideCharToMultiByte(
                CP_UTF8,
                0,
                lpszString,
                -1,
                &name[0],
                len,
                nullptr,
                nullptr
            );

            if (!name.empty() && name.back() == '\0')
                name.pop_back();
        }

        ss << " name=\"" << name << "\"";
    }

    ULONG_PTR dataValue = reinterpret_cast<ULONG_PTR>(hData);

    ss << " data=0x"
    << std::hex
    << dataValue
    << std::dec
    << " dataDec="
    << dataValue;

    Log(ss.str().c_str());

    return TRUE;
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

    BitBlt(
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

        COLORREF cNormal = 0;
        COLORREF cHot = 0;
        COLORREF cPressed = 0;
        COLORREF cDisabled = 0;

        HRESULT hrNormal = GetThemeColor(
            hTheme,
            BP_PUSHBUTTON,
            PBS_NORMAL,
            3803,
            &cNormal
        );

        HRESULT hrHot = GetThemeColor(
            hTheme,
            BP_PUSHBUTTON,
            PBS_HOT,
            3803,
            &cHot
        );

        HRESULT hrPressed = GetThemeColor(
            hTheme,
            BP_PUSHBUTTON,
            PBS_PRESSED,
            3803,
            &cPressed
        );

        HRESULT hrDisabled = GetThemeColor(
            hTheme,
            BP_PUSHBUTTON,
            PBS_DISABLED,
            3803,
            &cDisabled
        );

        ss << " normalHr=0x"
        << std::hex
        << static_cast<unsigned long>(hrNormal)
        << " normal=0x"
        << static_cast<unsigned int>(cNormal)

        << " hotHr=0x"
        << static_cast<unsigned long>(hrHot)
        << " hot=0x"
        << static_cast<unsigned int>(cHot)

        << " pressedHr=0x"
        << static_cast<unsigned long>(hrPressed)
        << " pressed=0x"
        << static_cast<unsigned int>(cPressed)

        << " disabledHr=0x"
        << static_cast<unsigned long>(hrDisabled)
        << " disabled=0x"
        << static_cast<unsigned int>(cDisabled)

        << std::dec;

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

static void LogGDIStateV61(
    const char* stage,
    HDC hdc,
    unsigned long long seq
)
{
    if (hdc == nullptr)
        return;

    COLORREF textColor = GetTextColor(hdc);
    COLORREF bkColor = GetBkColor(hdc);

    int bkMode = GetBkMode(hdc);
    int rop2 = GetROP2(hdc);
    int mapMode = GetMapMode(hdc);

    POINT origin = {};
    GetDCOrgEx(hdc, &origin);

    HGDIOBJ hFont = GetCurrentObject(hdc, OBJ_FONT);

    std::ostringstream ss;

    ss << "[V61] GDI "
       << stage
       << " seq=" << seq
       << " hDC=" << hdc
       << " text=0x" << std::hex
       << static_cast<unsigned int>(textColor)
       << " bk=0x"
       << static_cast<unsigned int>(bkColor)
       << std::dec
       << " bkMode=" << bkMode
       << " rop2=" << rop2
       << " map=" << mapMode
       << " org=(" << origin.x << "," << origin.y << ")"
       << " font=" << hFont;

    Log(ss.str());
}

LRESULT CALLBACK DialogWndProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
        if (uMsg == WM_DRAWITEM)
        {
            DRAWITEMSTRUCT* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);

            const unsigned long long drawSeq = ++g_drawSeq;
            const ULONGLONG drawTime = GetTickCount64();

            if (dis->hwndItem != nullptr)
            {
                char textBuf[256] = {};
                GetWindowTextA(dis->hwndItem, textBuf, sizeof(textBuf));

                std::ostringstream oss;
                oss << "[V60] DRAW seq=" << drawSeq
                    << " hwnd=" << dis->hwndItem
                    << " hDC=" << dis->hDC
                    << " state=0x" << std::hex << dis->itemState
                    << std::dec
                    << " text=\"" << textBuf << "\"";

                if (dis->hDC == g_lastDrawHDC)
                    oss << " SAME_HDC_AS_PREV";
                else
                    oss << " NEW_HDC";

                Log(oss.str());

                g_lastDrawHDC = dis->hDC;
            }
            
            if (dis != nullptr)
            {
                wchar_t buttonText[512] = {};

                GetWindowTextW(
                    dis->hwndItem,
                    buttonText,
                    _countof(buttonText)
                );

                // ========================= V71 STATE TEST =========================
                if (dis->hwndItem == g_hVariable)
                {
                    std::ostringstream ss;
                    ss << "[V71] VARIABLE_DRAW"
                    << " hwnd=" << HwndToString(dis->hwndItem)
                    << " CtlID=" << dis->CtlID
                    << " itemAction=0x" << std::hex << dis->itemAction
                    << " itemState=0x" << dis->itemState
                    << " itemData=" << reinterpret_cast<void*>(dis->itemData)
                    << " hDC=" << reinterpret_cast<void*>(dis->hDC)
                    << " rc=("
                    << std::dec
                    << dis->rcItem.left << ","
                    << dis->rcItem.top << ","
                    << dis->rcItem.right << ","
                    << dis->rcItem.bottom << ")";

                    Log(ss.str());
                }
                // ========================= V71 STATE TEST END =========================

                // ========================= V72 PARENT TEST =========================
                HWND hParent = GetParent(dis->hwndItem);

                std::ostringstream ps;
                ps << "[V72] VARIABLE_PARENT"
                << " hwnd=" << HwndToString(dis->hwndItem)
                << " parent=" << HwndToString(hParent);

                Log(ps.str());
                // ========================= V72 PARENT TEST END =========================

                std::ostringstream v44;

                v44 << "[V44] DRAWITEM"
                    << " hwnd=" << HwndToString(dis->hwndItem)
                    << " itemID=" << dis->CtlID
                    << " itemAction=0x"
                    << std::hex
                    << dis->itemAction
                    << " itemState=0x"
                    << dis->itemState
                    << std::dec
                    << " itemData="
                    << reinterpret_cast<void*>(dis->itemData)
                    << " rc=("
                    << dis->rcItem.left << ","
                    << dis->rcItem.top << ","
                    << dis->rcItem.right << ","
                    << dis->rcItem.bottom << ")"
                    << " hDC="
                    << reinterpret_cast<void*>(dis->hDC)
                    << " text=\"";

                char textUtf8[1024] = {};

                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    buttonText,
                    -1,
                    textUtf8,
                    sizeof(textUtf8),
                    nullptr,
                    nullptr
                );

                v44 << textUtf8 << "\"";

                Log(v44.str());

                std::ostringstream v54;

                v54 << "[V54] BUTTON META"
                    << " hwnd=" << HwndToString(dis->hwndItem)
                    << " text=\"" << textUtf8 << "\""
                    << " CtlID=" << dis->CtlID
                    << " itemState=0x" << std::hex << dis->itemState
                    << " style=0x"
                    << static_cast<unsigned long>(
                        GetWindowLongPtrW(dis->hwndItem, GWL_STYLE)
                    )
                    << " exStyle=0x"
                    << static_cast<unsigned long>(
                        GetWindowLongPtrW(dis->hwndItem, GWL_EXSTYLE)
                    )
                    << " GWLP_ID=0x"
                    << static_cast<unsigned long>(
                        GetWindowLongPtrW(dis->hwndItem, GWLP_ID)
                    )
                    << " USERDATA=0x"
                    << static_cast<unsigned long long>(
                        GetWindowLongPtrW(dis->hwndItem, GWLP_USERDATA)
                    )
                    << " FONT="
                    << HwndToString(reinterpret_cast<HWND>(
                        SendMessageW(
                            dis->hwndItem,
                            WM_GETFONT,
                            0,
                            0
                        )
                    ));
                Log(v54.str());

                EnumPropsExW(
                    dis->hwndItem,
                    V55_EnumPropProc,
                    0
                );
            }

            if (dis != nullptr && dis->CtlType == ODT_BUTTON && dis->hwndItem != nullptr && GetParent(dis->hwndItem) == g_hDialog)
            {
             
            // ========================= V59 =========================
            std::ostringstream oss;
                oss << "[V59] ENTRY surface seq=" << drawSeq;
                Log(oss.str());

                AnalyzeButtonSurfaceV27(
                dis->hDC,
                dis->rcItem,
                dis->hwndItem,
                dis->itemState
            );
            // ========================= V59 END =========================


            // ========================= V54 =========================
            UINT originalItemState = dis->itemState;

            // ========================= V58 BEFORE =========================
            Log("[V58] BEFORE_NATIVE surface");

            AnalyzeButtonSurfaceV27(
                dis->hDC,
                dis->rcItem,
                dis->hwndItem,
                dis->itemState
            );

            // ========================= V61 BEFORE =========================
            if (dis->hwndItem == g_hVariable)
            {
                LogGDIStateV61("BEFORE_NATIVE", dis->hDC, drawSeq);
            }

            // ========================= NATIVE =========================
            LRESULT nativeResult = CallWindowProcW(
                g_originalWndProc,
                hwnd,
                uMsg,
                wParam,
                lParam
            );

            // ========================= V61 AFTER =========================
            if (dis->hwndItem == g_hVariable)
            {
                LogGDIStateV61("AFTER_NATIVE", dis->hDC, drawSeq);
            }
            // ========================= V58 AFTER =========================
            Log("[V58] AFTER_NATIVE surface");

            AnalyzeButtonSurfaceV27(
                dis->hDC,
                dis->rcItem,
                dis->hwndItem,
                dis->itemState
            );

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

    // ========================= V68 CLEAN =========================
    LONG detourResult = DetourTransactionBegin();

    if (detourResult == NO_ERROR)
        detourResult = DetourUpdateThread(GetCurrentThread());

    //
    // ExtTextOutW больше НЕ hook'аем.
    // V62 уже доказал нужный факт и теперь только создаёт шум.
    //
    if (detourResult == NO_ERROR)
        detourResult = DetourAttach(
            &(PVOID&)g_realSetTextColor,
            HookSetTextColor
    );


    if (detourResult == NO_ERROR)
        detourResult = DetourTransactionCommit();
    else
        DetourTransactionAbort();

    if (detourResult == NO_ERROR)
    {
        Log("[V78] SetTextColor + internal color function hooks installed. ExtTextOutW hook disabled.");    
    }
    else
    {
        std::ostringstream ss;
        ss << "[V68] SetTextColor hook FAILED, error=" << detourResult;
        Log(ss.str());
    }
    InstallInternalColorHookV88();

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
