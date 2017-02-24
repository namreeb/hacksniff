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

#include "Log.hpp"
#include "MemorySniff.hpp"

#include <boost/filesystem.hpp>

#include <Windows.h>

#include <array>

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

static std::unique_ptr<MemorySniff> gMemorySniff;

extern "C" __declspec(dllexport) DWORD Load()
{
    std::array<char, MAX_PATH> filename;

    if (!GetModuleFileNameA(reinterpret_cast<HMODULE>(&__ImageBase), filename.data(), sizeof(filename)))
        return EXIT_FAILURE;

    auto const dir = boost::filesystem::path(filename.data()).parent_path().string();

    gLog.open(dir + "\\monitor.txt", std::fstream::out|std::fstream::app);

    gMemorySniff = std::make_unique<MemorySniff>();

    return EXIT_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD Free()
{
    gMemorySniff.reset();

    return EXIT_SUCCESS;
}