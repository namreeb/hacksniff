#include <sstream>
#include <iomanip>

#include "Log.hpp"

std::ofstream gLog;

const std::string BufferToString(LPCVOID buffer, SIZE_T length)
{
    LPCBYTE b = (LPCBYTE)buffer;
    std::stringstream str;

    for (unsigned int i = 0; i < length; ++i)
    {
        str << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (unsigned int)b[i];

        if (i != (length - 1))
            str << " ";
    }

    return str.str();
}