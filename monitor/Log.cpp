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

#include <sstream>
#include <iomanip>

std::ofstream gLog;

std::string BufferToString(LPCVOID buffer, SIZE_T length)
{
    return BufferToString(static_cast<LPCBYTE>(buffer), length);
}

std::string BufferToString(LPCBYTE buffer, SIZE_T length)
{
    auto const b = static_cast<LPCBYTE>(buffer);
    std::stringstream str;

    for (unsigned int i = 0; i < length; ++i)
    {
        str << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(b[i]);

        if (i != (length - 1))
            str << " ";
    }

    return str.str();
}