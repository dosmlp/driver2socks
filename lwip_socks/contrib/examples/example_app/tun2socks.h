#pragma once

#include <cstdint>
#include <cstddef> // for std::size_t
#include <string>
#include "socks5_auth.h"



#define MAX_LEN 256


using size_t = std::size_t;

typedef struct _DRIVER2SOCKSConfig {
	std::string socks5_address;
	uint16_t socks5_port;
	PBaseAuth socks5_auth;
	uint32_t udp_timeout;
} DRIVER2SOCKSConfig, *PDRIVER2SOCKSConfig;


void tun2socks_start(const DRIVER2SOCKSConfig*);