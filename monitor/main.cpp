#include <array>
#include <Windows.h>
#include <boost/filesystem.hpp>
#include <hadesmem/config.hpp>

#include "Log.hpp"
#include "MemorySniff.hpp"

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

extern "C" HADESMEM_DETAIL_DLLEXPORT DWORD Load()
{
    std::array<char, MAX_PATH> filename;

    if (!GetModuleFileName((HMODULE)&__ImageBase, filename.data(), sizeof(filename)))
        return EXIT_FAILURE;

    std::string dir = boost::filesystem::path(filename.data()).parent_path().string();

    gLog.open(dir + "\\monitor.txt", std::fstream::out|std::fstream::app);

    MemorySniff::Init();

    return EXIT_SUCCESS;
}

extern "C" HADESMEM_DETAIL_DLLEXPORT DWORD Free()
{
    MemorySniff::Deinit();

    return EXIT_SUCCESS;
}