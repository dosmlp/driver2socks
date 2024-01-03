#include "iocontext.h"

IoContext* IoContext::self_ = nullptr;
std::mutex IoContext::mutex_;