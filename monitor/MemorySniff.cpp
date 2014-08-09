#include <sstream>

#include <hadesmem/patcher.hpp>
#include <hadesmem/process.hpp>
#include <hadesmem/module.hpp>
#include <hadesmem/find_procedure.hpp>

#include "MemorySniff.hpp"
#include "Log.hpp"

MemorySniff *gMemorySniff;

MemorySniff::MemorySniff()
{
    const hadesmem::Process process(::GetCurrentProcessId());
    const hadesmem::Module kernel32(process, L"kernel32.dll");

    PVOID writeProcessMemory = hadesmem::FindProcedure(process, kernel32, "WriteProcessMemory");

    if (writeProcessMemory)
    {
        union
        {
            PVOID func;
            BOOL (WINAPI *FunctionPointer)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        } f;

        f.FunctionPointer = &MemorySniff::WriteProcessMemoryHook;

        m_writeProcessMemory.reset(new hadesmem::PatchDetour(process, writeProcessMemory, f.func));
        m_writeProcessMemory->Apply();
    }
}

BOOL WINAPI MemorySniff::WriteProcessMemoryHook(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    union
    {
        PVOID func;
        BOOL(WINAPI *FunctionPointer)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
    } f;

    f.func = gMemorySniff->m_writeProcessMemory->GetTrampoline<PVOID>();

    BOOL ret = (*f.FunctionPointer)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    HANDLE newHandle;

    if (!::DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &newHandle, PROCESS_QUERY_LIMITED_INFORMATION, false, 0))
        return ret;

    char processName[256];
    SIZE_T processNameLength = sizeof(processName);

    auto nameRet = ::QueryFullProcessImageNameA(newHandle, 0, processName, &processNameLength);

    gLog << "WriteProcessMemory(" << (nameRet ? processName : "(unknown module name)") << ") address = 0x" << std::uppercase << std::hex
         << (unsigned long)lpBaseAddress << " size = " << std::dec << nSize << " Buffer: " << BufferToString(lpBuffer, nSize) << std::endl;

    return ret;
}