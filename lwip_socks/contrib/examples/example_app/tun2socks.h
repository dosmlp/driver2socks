#pragma once

#include <cstdint>
#include <cstddef> // for std::size_t
#include <memory>
#include <string>
#include "socks5_auth.h"



#define MAX_LEN 256


using size_t = std::size_t;

struct DRIVER2SOCKSConfig {
	typedef std::shared_ptr<DRIVER2SOCKSConfig> Ptr;
	bool enable_ipv6;
	std::string proxy_username;
	std::string proxy_password;
	std::string socks5_address;
	uint16_t socks5_port;
	uint32_t udp_timeout;
	DRIVER2SOCKSConfig()
	{
		enable_ipv6 = false;
		socks5_port = 0;
		udp_timeout = 5000;
	}
};


void tun2socks_start(const DRIVER2SOCKSConfig*);