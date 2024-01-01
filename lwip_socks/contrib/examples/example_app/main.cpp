#include "WindivertDriver.h"
#include "socks5.h"
#include "lwipstack.h"
#include "tun2socks.h"
#include "DbgHelp.h"
#include <filesystem>
#include <Windows.h>

#pragma comment(lib, "dbghelp.lib")

LONG unhandledExceptionFilterEx(PEXCEPTION_POINTERS pException)
{
    HANDLE hFile = CreateFile(std::to_wstring(GetCurrentProcessId()).append(L".dmp").data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

	std::string path = std::filesystem::current_path().string();
	SetUnhandledExceptionFilter(unhandledExceptionFilterEx);

	DRIVER2SOCKSConfig cfg;
	cfg.socks5_address = "127.0.0.1";
	cfg.socks5_port = 7890;
	tun2socks_start(&cfg);
	std::cout << "__________________________________________\n";
	return 0;
}
