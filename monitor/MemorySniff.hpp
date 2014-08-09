#pragma once

#include <Windows.h>

#include <hadesmem/patcher.hpp>

class MemorySniff
{
    public:
        MemorySniff();

    private:
        std::unique_ptr<hadesmem::PatchDetour> m_writeProcessMemory;

        static BOOL WINAPI WriteProcessMemoryHook(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
};

extern MemorySniff *gMemorySniff;