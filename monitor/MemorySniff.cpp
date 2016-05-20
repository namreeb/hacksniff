#include <array>

#include <boost/date_time/posix_time/posix_time.hpp>

#include <hadesmem/patcher.hpp>
#include <hadesmem/process.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/find_procedure.hpp>

#include "MemorySniff.hpp"
#include "Log.hpp"

MemorySniff::MemorySniff()
{
    const hadesmem::Process process(::GetCurrentProcessId());
    const hadesmem::Module kernel32(process, L"kernel32.dll");

    auto const writeProcessMemory = hadesmem::FindProcedure(process, kernel32, "NtWriteVirtualMemory");

    if (writeProcessMemory)
    {
        auto const orig = hadesmem::detail::AliasCast<WriteProcessMemoryT>(writeProcessMemory);

        m_writeProcessMemory = std::make_unique<hadesmem::PatchDetour<WriteProcessMemoryT>>(process, orig,
            [this](hadesmem::PatchDetourBase *detour, HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
            {
                return this->WriteProcessMemoryHook(detour, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
            }
        );

        m_writeProcessMemory->Apply();
    }

    auto const readProcessMemory = hadesmem::FindProcedure(process, kernel32, "NtReadVirtualMemory");

    if (readProcessMemory)
    {
        auto const orig = hadesmem::detail::AliasCast<ReadProcessMemoryT>(readProcessMemory);

        m_readProcessMemory = std::make_unique<hadesmem::PatchDetour<ReadProcessMemoryT>>(process, orig,
            [this](hadesmem::PatchDetourBase *detour, HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
            {
                return this->ReadProcessMemoryHook(detour, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
            }
        );

        m_readProcessMemory->Apply();
    }
}

BOOL MemorySniff::WriteProcessMemoryHook(hadesmem::PatchDetourBase *detour, HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    HANDLE newHandle;

    std::string processName = "(unknown module name)";
    std::string originalData = "(unable to read)";

    auto memoryChanged = true;

    if (::DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &newHandle, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, 0))
    {
        std::array<char, MAX_PATH> processNameBuff;
        SIZE_T processNameLength = processNameBuff.size();

        if (::QueryFullProcessImageNameA(newHandle, 0, processNameBuff.data(), &processNameLength))
            processName = processNameBuff.data();

        std::vector<BYTE> originalDataBuff(nSize);
        SIZE_T readSize;

        auto readMemoryTrampoline = m_readProcessMemory->IsApplied() ? m_readProcessMemory->GetTrampolineT<ReadProcessMemoryT>() : &::ReadProcessMemory;

        if ((*readMemoryTrampoline)(newHandle, lpBaseAddress, &originalDataBuff[0], nSize, &readSize))
            originalData = BufferToString(&originalDataBuff[0], readSize);

        // also give a warning if they didnt read as much as they wanted to
        if (readSize != nSize)
            originalData += " (read incomplete)";

        if (!memcmp(lpBuffer, &originalDataBuff[0], readSize))
            memoryChanged = false;
    }

    auto trampoline = detour->GetTrampolineT<WriteProcessMemoryT>();

    auto const ret = (*trampoline)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    // only bother logging the write if we are changing the value of the memory.  this helps reduce spam in some cases.
    if (memoryChanged)
    {
        auto const p = boost::posix_time::from_time_t(time(nullptr));

        gLog << "[" << p << "]: NtWriteVirtualMemory(" << processName << ") 0x" << std::uppercase << std::hex << reinterpret_cast<unsigned long>(lpBaseAddress)
             << " Size: " << std::dec << nSize << " Original data: " << originalData << " New data: " << BufferToString(lpBuffer, nSize);

        if (!ret)
            gLog << " (FAILED)";

        gLog << std::endl;
    }

    return ret;
}

BOOL MemorySniff::ReadProcessMemoryHook(hadesmem::PatchDetourBase *detour, HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
    HANDLE newHandle;

    std::string processName = "(unknown module name)";

    if (::DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &newHandle, PROCESS_QUERY_LIMITED_INFORMATION, false, 0))
    {
        std::array<char, MAX_PATH> processNameBuff;
        SIZE_T processNameLength = processNameBuff.size();

        if (::QueryFullProcessImageNameA(newHandle, 0, processNameBuff.data(), &processNameLength))
            processName = processNameBuff.data();
    }

    auto const trampoline = detour->GetTrampolineT<ReadProcessMemoryT>();
    auto const ret = (*trampoline)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    auto const logKey = LogEntryIndex(lpBaseAddress, nSize);

    bool memoryChanged;

    if (m_readLog.find(logKey) == m_readLog.end())
    {
        m_readLog[logKey].resize(nSize);
        memcpy(&m_readLog[logKey][0], lpBuffer, nSize);

        memoryChanged = true;
    }
    else
        memoryChanged = !!memcmp(&m_readLog[logKey][0], lpBuffer, nSize);

    if (memoryChanged)
    {
        auto const p = boost::posix_time::from_time_t(time(nullptr));

        gLog << "[" << p << "]: NtReadVirtualMemory(" << processName << ") 0x" << std::uppercase << std::hex << reinterpret_cast<unsigned long>(lpBaseAddress)
            << " Size: " << std::dec << nSize << " Data: " << BufferToString(lpBuffer, nSize);

        if (!ret)
            gLog << " (FAILED)";

        gLog << std::endl;
    }

    return ret;
}