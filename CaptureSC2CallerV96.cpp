static void CaptureSC2CallerV96(COLORREF color)
{
    CONTEXT ctx{};
    RtlCaptureContext(&ctx);

    DWORD64 imageBase = 0;

    PRUNTIME_FUNCTION functionEntry =
        RtlLookupFunctionEntry(
            ctx.Rip,
            &imageBase,
            nullptr);

    if (!functionEntry)
    {
        Log("[V96] RtlLookupFunctionEntry failed.");
        return;
    }

    PVOID handlerData = nullptr;
    DWORD64 establisherFrame = 0;

    CONTEXT callerCtx = ctx;

    // ========================= V103 =========================
    // Расширяем unwind только до 4 кадров.
    // FRAME=2 уже подтверждён как реальный SC2 call site.
    // FRAME=3/4 нужны для поиска ближайших caller'ов.
    // Ничего не изменяем.
    // =========================================================

    for (int frame = 1; frame <= 4; ++frame)
    {
        PRUNTIME_FUNCTION frameFunction =
            RtlLookupFunctionEntry(
                callerCtx.Rip,
                &imageBase,
                nullptr);

        if (!frameFunction)
        {
            std::ostringstream s;

            s << "[V103] UNWIND FAILED"
            << " frame=" << frame
            << " RIP="
            << reinterpret_cast<void*>(callerCtx.Rip);

            Log(s.str());
            return;
        }

        PVOID frameHandlerData = nullptr;
        DWORD64 frameEstablisherFrame = 0;

        RtlVirtualUnwind(
            UNW_FLAG_NHANDLER,
            imageBase,
            callerCtx.Rip,
            frameFunction,
            &callerCtx,
            &frameHandlerData,
            &frameEstablisherFrame,
            nullptr);

        DWORD64 frameImageBase = 0;

        PRUNTIME_FUNCTION currentFunction =
            RtlLookupFunctionEntry(
                callerCtx.Rip,
                &frameImageBase,
                nullptr);

        std::ostringstream s;

        s << "[V103] FRAME="
        << frame
        << " RIP="
        << reinterpret_cast<void*>(callerCtx.Rip)
        << " RSP="
        << reinterpret_cast<void*>(callerCtx.Rsp)
        << " RDI="
        << reinterpret_cast<void*>(callerCtx.Rdi)
        << " RSI="
        << reinterpret_cast<void*>(callerCtx.Rsi)
        << " R15="
        << reinterpret_cast<void*>(callerCtx.R15);

        if (currentFunction != nullptr)
        {
            s << " MODULE_BASE="
            << reinterpret_cast<void*>(frameImageBase)
            << " RVA=0x"
            << std::hex
            << std::uppercase
            << (callerCtx.Rip - frameImageBase);
        }

        Log(s.str());

        if (frame == 3)
        {
            DumpCodeAtRvaV77(
                reinterpret_cast<void*>(callerCtx.Rip),
                0x1F2DAED,
                0x120,
                0x20
            );

            AnalyzeRelativeCallsV105(
                reinterpret_cast<void*>(callerCtx.Rip),
                0x1F2DAED,
                0x120,
                0x20
            );

            DumpContainingFunctionV106(
                hSc2,
                static_cast<uintptr_t>(callerCtx.Rip),
                "FRAME3"
            );
        }
    }

    // ========================= V103 END =========================

    std::ostringstream s;

    s << "[V96] UNWIND"
      << " callerRIP="
      << reinterpret_cast<void*>(callerCtx.Rip)
      << " callerRSP="
      << reinterpret_cast<void*>(callerCtx.Rsp)
      << " RDI="
      << reinterpret_cast<void*>(callerCtx.Rdi)
      << " RSI="
      << reinterpret_cast<void*>(callerCtx.Rsi)
      << " R15="
      << reinterpret_cast<void*>(callerCtx.R15);

    Log(s.str());

    //
    // RDI should be the original RDX of
    // SC2 + 0x1F4ED30.
    //
    const uintptr_t originalRDX =
        static_cast<uintptr_t>(callerCtx.Rdi);

    DumpColorStateV98(originalRDX);
    //
    // RSI should be the original RCX.
    //
    const uintptr_t originalRCX =
        static_cast<uintptr_t>(callerCtx.Rsi);

    AnalyzeColorStateV99(originalRCX, originalRDX, color);


    if (originalRDX == 0 || originalRCX == 0)
    {
        Log("[V96] Invalid recovered RCX/RDX.");
        return;
    }

    ULONG_PTR state18 = 0;
    ULONG_PTR colorB0 = 0;
    ULONG_PTR colorB4 = 0;
    ULONG_PTR colorB8 = 0;

    const bool okState =
        ReadQwordSafeV96(
            originalRDX + 0x18,
            state18);

    const bool okB0 =
        ReadQwordSafeV96(
            originalRCX + 0xB0,
            colorB0);

    const bool okB4 =
        ReadQwordSafeV96(
            originalRCX + 0xB4,
            colorB4);

    const bool okB8 =
        ReadQwordSafeV96(
            originalRCX + 0xB8,
            colorB8);

    std::ostringstream v;

    v << "[V97] COLOR OBJECT"
      << " RCX="
      << reinterpret_cast<void*>(originalRCX)
      << " RDX="
      << reinterpret_cast<void*>(originalRDX);

    if (okState)
        v << " state18=0x"
          << std::hex
          << state18;
    else
        v << " state18=READ_FAILED";

    if (okB0)
        v << " B0=0x"
          << std::hex
          << colorB0;
    else
        v << " B0=READ_FAILED";

    if (okB4)
        v << " B4=0x"
          << std::hex
          << colorB4;
    else
        v << " B4=READ_FAILED";

    if (okB8)
        v << " B8=0x"
          << std::hex
          << colorB8;
    else
        v << " B8=READ_FAILED";

    Log(v.str());
}
