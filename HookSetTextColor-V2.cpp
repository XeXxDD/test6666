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

        if (color == 0xA000 || color == 0x804040)
        {
            unsigned char* p =
                reinterpret_cast<unsigned char*>(caller);

            std::ostringstream ss;
            ss << "[V92] COLOR"
            << " color=0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned int>(color)
            << " caller=" << caller;

            Log(ss.str());

            for (int offset = -64; offset < 0; offset += 16)
            {
                std::ostringstream line;

                line << "[V92] "
                    << (offset < 0 ? "-" : "+")
                    << "0x"
                    << std::hex
                    << std::setw(2)
                    << std::setfill('0')
                    << (offset < 0 ? -offset : offset)
                    << ":";

                for (int i = 0; i < 16; ++i)
                {
                    line << " "
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<unsigned int>(
                                p[offset + i]
                            );
                }

                Log(line.str());
            }
        }

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
                    InspectColorCallSiteV93();
                    DumpColorFunctionBytesV115();
                    CaptureColorContextV94();
                    CaptureSC2CallerV96(color);
                }
            }
        }
        // ========================= V75 RDI TEST END =========================

        // ========================= V67  =========================

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
