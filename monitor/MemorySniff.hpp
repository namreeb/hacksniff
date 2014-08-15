#pragma once

#include <Windows.h>
#include <map>

#include <hadesmem/patcher.hpp>

class MemorySniff
{
    public:
        static void Init();
        static void Deinit();

    private:
        static std::unique_ptr<hadesmem::PatchDetour> m_writeProcessMemory;
        static std::unique_ptr<hadesmem::PatchDetour> m_readProcessMemory;

        static BOOL WINAPI WriteProcessMemoryHook(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        static BOOL WINAPI ReadProcessMemoryHook(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);

        typedef std::pair<LPCVOID, SIZE_T> LogEntryIndex;

        static std::map<LogEntryIndex, std::vector<BYTE>> m_readLog;
};
