#include <Windows.h>
#include <boost/filesystem.hpp>
#include <hadesmem/config.hpp>

#include "Log.hpp"
#include "MemorySniff.hpp"

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

extern "C" HADESMEM_DETAIL_DLLEXPORT DWORD Load()
{
    char filename[1024];

    if (!GetModuleFileName((HMODULE)&__ImageBase, filename, sizeof(filename)))
        return EXIT_FAILURE;

    std::string dir = boost::filesystem::path(filename).parent_path().string();

    gLog.open(dir + "\\monitor.txt", std::fstream::out|std::fstream::app);

    gMemorySniff = new MemorySniff();

    return EXIT_SUCCESS;
}

extern "C" HADESMEM_DETAIL_DLLEXPORT DWORD Free()
{
    delete gMemorySniff;

    return EXIT_SUCCESS;
}