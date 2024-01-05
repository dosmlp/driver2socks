#include "WindivertDriver.h"
#include "lwipstack.h"
#include "tun2socks.h"
#include "DbgHelp.h"
#include "nlohmann/json.hpp"
#include <filesystem>
#include <Windows.h>
#include <fstream>
#include "app_config.h"
using namespace nlohmann;

#pragma comment(lib, "dbghelp.lib")

LONG unhandledExceptionFilterEx(PEXCEPTION_POINTERS pException)
{
    HANDLE hFile = CreateFileW(std::to_wstring(GetCurrentProcessId()).append(L".dmp").data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    MINIDUMP_EXCEPTION_INFORMATION mdei;
    if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE)) {
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = pException;
        mdei.ClientPointers = FALSE;

        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &mdei, NULL, NULL);

        CloseHandle(hFile);
        return TRUE;
    }
}

int main(int argc, char* argv)
{
	SetUnhandledExceptionFilter(unhandledExceptionFilterEx);

    std::ifstream config_file("cfg.json",std::ios::in,std::ios::binary);

    json doc = json::parse(config_file,nullptr,false);

	driver2socks::Driver2SocksConfig cfg;
	cfg.socks5_server_ip = "127.0.0.1";
	cfg.socks5_server_port = 7890;
	tun2socks_start(&cfg);
	std::cout << "__________________________________________\n";
	return 0;
}
