#pragma once

#include <cstdint>
#include <cstddef> // for std::size_t
#include <memory>
#include <string>
#include "app_config.h"


#define MAX_LEN 256


using size_t = std::size_t;


void tun2socks_start(const DRIVER2SOCKSConfig*);