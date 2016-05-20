#pragma once

#include <map>

#include <Windows.h>

#include <hadesmem/patcher.hpp>

class MemorySniff
{
    public:
        MemorySniff();

        using WriteProcessMemoryT = BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        using ReadProcessMemoryT = BOOL(WINAPI *)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);

    private:
        BOOL WriteProcessMemoryHook(hadesmem::PatchDetourBase *, HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        BOOL ReadProcessMemoryHook(hadesmem::PatchDetourBase *, HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);

        typedef std::pair<LPCVOID, SIZE_T> LogEntryIndex;

        std::unique_ptr<hadesmem::PatchDetour<WriteProcessMemoryT>> m_writeProcessMemory;
        std::unique_ptr<hadesmem::PatchDetour<ReadProcessMemoryT>> m_readProcessMemory;

        std::map<LogEntryIndex, std::vector<BYTE>> m_readLog;
};
