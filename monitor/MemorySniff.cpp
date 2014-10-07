#include <boost/date_time/posix_time/posix_time.hpp>
#include <hadesmem/patcher.hpp>
#include <hadesmem/process.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/find_procedure.hpp>

#include "MemorySniff.hpp"
#include "Log.hpp"

std::unique_ptr<hadesmem::PatchDetour> MemorySniff::m_writeProcessMemory;
std::unique_ptr<hadesmem::PatchDetour> MemorySniff::m_readProcessMemory;
std::map<MemorySniff::LogEntryIndex, std::vector<BYTE>> MemorySniff::m_readLog;

void MemorySniff::Init()
{
    const hadesmem::Process process(::GetCurrentProcessId());
    const hadesmem::Module kernel32(process, L"kernel32.dll");

    PVOID writeProcessMemory = hadesmem::FindProcedure(process, kernel32, "NtWriteVirtualMemory");

    if (writeProcessMemory)
    {
        union
        {
            PVOID func;
            BOOL(WINAPI *FunctionPointer)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        } f;

        f.FunctionPointer = &MemorySniff::WriteProcessMemoryHook;

        m_writeProcessMemory.reset(new hadesmem::PatchDetour(process, writeProcessMemory, f.func));
        m_writeProcessMemory->Apply();
    }

    PVOID readProcessMemory = hadesmem::FindProcedure(process, kernel32, "NtReadVirtualMemory");

    if (readProcessMemory)
    {
        union
        {
            PVOID func;
            BOOL(WINAPI *FunctionPointer)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
        } f;

        f.FunctionPointer = &MemorySniff::ReadProcessMemoryHook;

        m_readProcessMemory.reset(new hadesmem::PatchDetour(process, readProcessMemory, f.func));
        m_readProcessMemory->Apply();
    }
}

void MemorySniff::Deinit()
{
    m_writeProcessMemory->Remove();
    m_readProcessMemory->Remove();
}

BOOL WINAPI MemorySniff::WriteProcessMemoryHook(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    HANDLE newHandle;

    std::string processName = "(unknown module name)";
    std::string originalData = "(unable to read)";

    bool memoryChanged = true;

    if (::DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &newHandle, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, 0))
    {
        char processNameBuff[256];
        SIZE_T processNameLength = sizeof(processNameBuff);

        if (::QueryFullProcessImageNameA(newHandle, 0, processNameBuff, &processNameLength))
            processName = processNameBuff;

        std::vector<BYTE> originalDataBuff(nSize);
        SIZE_T readSize;

        auto readMemoryTrampoline = m_readProcessMemory->IsApplied() ?
            m_readProcessMemory->GetTrampoline<BOOL(WINAPI *)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *)>() : &ReadProcessMemory;

        if ((*readMemoryTrampoline)(newHandle, lpBaseAddress, &originalDataBuff[0], nSize, &readSize))
            originalData = BufferToString(&originalDataBuff[0], readSize);

        // also give a warning if they didnt read as much as they wanted to
        if (readSize != nSize)
            originalData += " (read incomplete)";

        if (!memcmp(lpBuffer, &originalDataBuff[0], readSize))
            memoryChanged = false;
    }

    auto trampoline = m_writeProcessMemory->GetTrampoline<BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *)>();

    BOOL ret = (*trampoline)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    // only bother logging the write if we are changing the value of the memory.  this helps reduce spam in some cases.
    if (memoryChanged)
    {
        const boost::posix_time::ptime p = boost::posix_time::from_time_t(time(nullptr));

        gLog << "[" << p << "]: NtWriteVirtualMemory(" << processName << ") 0x" << std::uppercase << std::hex << (unsigned long)lpBaseAddress
             << " Size: " << std::dec << nSize << " Original data: " << originalData << " New data: " << BufferToString(lpBuffer, nSize);

        if (!ret)
            gLog << " (FAILED)";

        gLog << std::endl;
    }

    return ret;
}

BOOL WINAPI MemorySniff::ReadProcessMemoryHook(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
    HANDLE newHandle;

    std::string processName = "(unknown module name)";

    if (::DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &newHandle, PROCESS_QUERY_LIMITED_INFORMATION, false, 0))
    {
        char processNameBuff[1024];
        SIZE_T processNameLength = sizeof(processNameBuff);

        if (::QueryFullProcessImageNameA(newHandle, 0, processNameBuff, &processNameLength))
            processName = processNameBuff;
    }

    auto const trampoline = m_readProcessMemory->GetTrampoline<BOOL(WINAPI *)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *)>();

    BOOL ret = (*trampoline)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

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
        const boost::posix_time::ptime p = boost::posix_time::from_time_t(time(nullptr));

        gLog << "[" << p << "]: NtReadVirtualMemory(" << processName << ") 0x" << std::uppercase << std::hex << (unsigned long)lpBaseAddress
            << " Size: " << std::dec << nSize << " Data: " << BufferToString(lpBuffer, nSize);

        if (!ret)
            gLog << " (FAILED)";

        gLog << std::endl;
    }

    return ret;
}