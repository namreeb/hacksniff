#pragma once

#include <Windows.h>
#include <fstream>
#include <string>

extern std::ofstream gLog;

const std::string BufferToString(LPCVOID, SIZE_T);