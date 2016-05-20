#include <array>
#include <Windows.h>

#include <boost/filesystem.hpp>

#include "Log.hpp"
#include "MemorySniff.hpp"

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

static std::unique_ptr<MemorySniff> gMemorySniff;

extern "C" __declspec(dllexport) DWORD Load()
{
    std::array<char, MAX_PATH> filename;

    if (!GetModuleFileNameA((HMODULE)&__ImageBase, filename.data(), sizeof(filename)))
        return EXIT_FAILURE;

    std::string dir = boost::filesystem::path(filename.data()).parent_path().string();

    gLog.open(dir + "\\monitor.txt", std::fstream::out|std::fstream::app);

    gMemorySniff = std::make_unique<MemorySniff>();

    return EXIT_SUCCESS;
}

extern "C" __declspec(dllexport) DWORD Free()
{
    gMemorySniff.reset(nullptr);

    return EXIT_SUCCESS;
}