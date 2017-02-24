/*
*  hacksniff - a tool for monitoring how a target process interacts with another process
*
*  Copyright (C) 2017 namreeb legal@namreeb.org http://github.com/namreeb
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License along
*  with this program; if not, write to the Free Software Foundation, Inc.,
*  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#pragma once

#include <hadesmem/patcher.hpp>

#include <Windows.h>

#include <map>

class MemorySniff
{
    public:
        MemorySniff();

        using WriteProcessMemoryT = BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        using ReadProcessMemoryT = BOOL(WINAPI *)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);

    private:
        BOOL WriteProcessMemoryHook(hadesmem::PatchDetourBase *, HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *) const;
        BOOL ReadProcessMemoryHook(hadesmem::PatchDetourBase *, HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);

        typedef std::pair<LPCVOID, SIZE_T> LogEntryIndex;

        std::unique_ptr<hadesmem::PatchDetour<WriteProcessMemoryT>> m_writeProcessMemory;
        std::unique_ptr<hadesmem::PatchDetour<ReadProcessMemoryT>> m_readProcessMemory;

        std::map<LogEntryIndex, std::vector<BYTE>> m_readLog;
};
