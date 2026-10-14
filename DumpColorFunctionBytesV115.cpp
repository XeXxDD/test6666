void DumpColorFunctionBytesV115()
{
    HMODULE hSc2 =
        GetModuleHandleW(L"SC2Editor_x64.exe");

    if (!hSc2)
    {
        Log("[V115] SC2Editor_x64.exe not found.");
        return;
    }

    uintptr_t base =
        reinterpret_cast<uintptr_t>(hSc2);

    uintptr_t function =
        base + 0x1F4ED30;

    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(function);

    std::ostringstream s;

    s << std::hex
      << "[V115] FUNCTION=" << function;

    Log(s.str());

    for (size_t offset = 0; offset < 0xA0; offset += 0x10)
    {
        std::ostringstream line;

        line << std::hex
             << "[V115] +0x"
             << std::setw(2)
             << std::setfill('0')
             << offset
             << ":";

        for (size_t j = 0; j < 0x10; ++j)
        {
            line << " "
                 << std::setw(2)
                 << std::setfill('0')
                 << static_cast<unsigned int>(p[offset + j]);
        }

        Log(line.str());
    }

    Log("[V115] END.");
}
