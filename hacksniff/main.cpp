// hacksniff loader

#include <string>
#include <iostream>
#include <vector>

#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <hadesmem/injector.hpp>

int main(int argc, char *argv[])
{
    std::wstring dll, program, logfile;
    std::string exportFunc;

    try
    {
        boost::program_options::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "display help message")
            ("logfile,l", boost::program_options::wvalue<std::wstring>(&logfile)->default_value(L"snifflog.txt", "snifflog.txt"), "log file")
            ("dll,d", boost::program_options::wvalue<std::wstring>(&dll)->default_value(L"monitor.dll", "monitor.dll"), "dll to inject into program")
            ("export,e", boost::program_options::value<std::string>(&exportFunc)->default_value("Load"), "export to call once dll is injected")
            ("program,p", boost::program_options::wvalue<std::wstring>(&program)->required(), "program name");

        boost::program_options::variables_map vm;

        try
        {
            boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
            boost::program_options::notify(vm);

            if (vm.count("help"))
            {
                std::cout << desc << std::endl;
                return EXIT_FAILURE;
            }
        }
        catch (boost::program_options::error const &e)
        {
            std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
            std::cerr << desc << std::endl;
            return EXIT_FAILURE;
        }

        std::vector<std::wstring> createArgs;

        const hadesmem::CreateAndInjectData injectData =
            hadesmem::CreateAndInject(program, L"", std::begin(createArgs), std::end(createArgs), dll, exportFunc, hadesmem::InjectFlags::kPathResolution);

        std::wcout << L"Injected.  Process ID: " << injectData.GetProcess() << std::endl;
    }
    catch (std::exception const &e)
    {
        std::cerr << "ERROR: " << std::endl;
        std::cerr << boost::diagnostic_information(e) << std::endl;
    }

    return EXIT_SUCCESS;
}