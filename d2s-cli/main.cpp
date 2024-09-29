#include "windivert_driver.h"
#include "lwipstack.h"
#include "driver2socks.h"
#include "DbgHelp.h"
#include "nlohmann/json.hpp"
#include <filesystem>
#include <Windows.h>
#include <fstream>
#include "base/xlog.h"
#include "base/exceptiondump.h"
#include "app_config.h"
#include "adapters_info.h"
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

int main(int argc, char** argv)
{
    ExceptionDump::Init("./");
    // SetUnhandledExceptionFilter(unhandledExceptionFilterEx);
    XLogMgr::get()->InitLog("./","d2s-cli","d2s-cli");

    std::ifstream config_file("cfg.json",std::ios::in,std::ios::binary);
    driver2socks::Driver2SocksConfig cfg;

    json doc = json::parse(config_file,nullptr,false);
    if (doc.is_discarded()) {
        std::cerr << "json parse error\n";
        return -1;
    }

    driver2socks::from_json(doc,cfg);
    driver2socks_start(&cfg);
	return 0;
}
