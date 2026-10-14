static void AnalyzeColorStateV99(
    uintptr_t rcx,
    uintptr_t rdx,
    COLORREF color)
{
    uint32_t state18 = 0;
    uint32_t b0 = 0;
    uint32_t b4 = 0;
    uint32_t b8 = 0;

    const bool ok18 = ReadDwordSafeV116(rdx + 0x18, state18);
    const bool okB0 = ReadDwordSafeV116(rcx + 0xB0, b0);
    const bool okB4 = ReadDwordSafeV116(rcx + 0xB4, b4);
    const bool okB8 = ReadDwordSafeV116(rcx + 0xB8, b8);

    if (!ok18 || !okB0 || !okB4 || !okB8)
    {
        std::ostringstream s;

        s << "[V116] READ_FAILED"
        << " ok18=" << ok18
        << " okB0=" << okB0
        << " okB4=" << okB4
        << " okB8=" << okB8
        << " RCX=" << reinterpret_cast<void*>(rcx)
        << " RDX=" << reinterpret_cast<void*>(rdx);

        Log(s.str());
        return;
    }

    std::ostringstream s;

    const bool bit0 = ((state18 >> 0) & 1) != 0;
    const bool bit2 = ((state18 >> 2) & 1) != 0;

    ULONG_PTR selectedValue = 0;

    if (bit2)
    {
        selectedValue = b4;
    }
    else if (bit0)
    {
        selectedValue = b8;
    }
    else
    {
        selectedValue = b0;
    }

    s << "[V116] COLOR STATE"
    << " color=0x" << std::hex
    << static_cast<unsigned int>(color)
    << " RCX=" << reinterpret_cast<void*>(rcx)
    << " RDX=" << reinterpret_cast<void*>(rdx)
    << " state18=0x" << state18
    << " bit0=" << bit0
    << " bit1=" << ((state18 >> 1) & 1)
    << " bit2=" << bit2
    << " bit3=" << ((state18 >> 3) & 1)
    << " B0=0x" << b0
    << " B4=0x" << b4
    << " B8=0x" << b8
    << " SELECTED=0x" << selectedValue;

    Log(s.str());
}
