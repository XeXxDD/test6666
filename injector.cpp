#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD FindProcessId(const wchar_t* processName)
{
    DWORD result = 0;

    HANDLE snapshot =
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, processName) == 0)
            {
                result = entry.th32ProcessID;
                break;
            }

        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    return result;
}

bool InjectDLL(DWORD pid, const std::wstring& dllPath)
{
    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!process)
    {
        std::cout
            << "OpenProcess failed. Error="
            << GetLastError()
            << "\n";

        return false;
    }

    SIZE_T size =
        (dllPath.size() + 1) * sizeof(wchar_t);

    LPVOID remoteMemory =
        VirtualAllocEx(
            process,
            nullptr,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

    if (!remoteMemory)
    {
        std::cout
            << "VirtualAllocEx failed. Error="
            << GetLastError()
            << "\n";

        CloseHandle(process);
        return false;
    }

    if (!WriteProcessMemory(
            process,
            remoteMemory,
            dllPath.c_str(),
            size,
            nullptr))
    {
        std::cout
            << "WriteProcessMemory failed. Error="
            << GetLastError()
            << "\n";

        VirtualFreeEx(
            process,
            remoteMemory,
            0,
            MEM_RELEASE
        );

        CloseHandle(process);

        return false;
    }

    HMODULE kernel32 =
        GetModuleHandleW(L"kernel32.dll");

    FARPROC loadLibrary =
        GetProcAddress(
            kernel32,
            "LoadLibraryW"
        );

    if (!loadLibrary)
    {
        std::cout << "GetProcAddress failed.\n";

        VirtualFreeEx(
            process,
            remoteMemory,
            0,
            MEM_RELEASE
        );

        CloseHandle(process);

        return false;
    }

    HANDLE thread =
        CreateRemoteThread(
            process,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(
                loadLibrary
            ),
            remoteMemory,
            0,
            nullptr
        );

    if (!thread)
    {
        std::cout
            << "CreateRemoteThread failed. Error="
            << GetLastError()
            << "\n";

        VirtualFreeEx(
            process,
            remoteMemory,
            0,
            MEM_RELEASE
        );

        CloseHandle(process);

        return false;
    }

    WaitForSingleObject(thread, INFINITE);

    DWORD exitCode = 0;

    GetExitCodeThread(
        thread,
        &exitCode
    );

    std::cout
        << "LoadLibrary remote result: 0x"
        << std::hex
        << exitCode
        << std::dec
        << "\n";

    CloseHandle(thread);

    VirtualFreeEx(
        process,
        remoteMemory,
        0,
        MEM_RELEASE
    );

    CloseHandle(process);

    return exitCode != 0;
}

int wmain()
{
    std::wcout
        << L"=== SC2 hook diagnostic injector ===\n\n";

    DWORD pid =
        FindProcessId(L"SC2Editor_x64.exe");

    if (!pid)
    {
        std::wcout
            << L"SC2Editor_x64.exe not found.\n";

        return 1;
    }

    std::wcout
        << L"Found PID: "
        << pid
        << L"\n";

    wchar_t dllPath[MAX_PATH] = {};

    GetFullPathNameW(
        L"hook_diag.dll",
        MAX_PATH,
        dllPath,
        nullptr
    );

    std::wcout
        << L"DLL: "
        << dllPath
        << L"\n";

    if (!InjectDLL(pid, dllPath))
    {
        std::wcout
            << L"Injection failed.\n";

        return 1;
    }

    std::wcout
        << L"Injection completed.\n";
    std::wcout
        << L"Check hook_diag.log next to hook_diag.dll.\n";

    return 0;
}