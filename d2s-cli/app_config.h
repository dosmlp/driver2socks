#pragma once

#include "nlohmann/json.hpp"

namespace driver2socks {
    using nlohmann::json;

    #ifndef NLOHMANN_UNTYPED_driver2socks_HELPER
    #define NLOHMANN_UNTYPED_driver2socks_HELPER
    inline json get_untyped(const json & j, const char * property) {
        if (j.find(property) != j.end()) {
            return j.at(property).get<json>();
        }
        return json();
    }

    inline json get_untyped(const json & j, std::string property) {
        return get_untyped(j, property.data());
    }
    #endif

    struct Driver2SocksConfig {
        bool enable_ipv6;
        std::string socks5_server_ip;
        uint16_t socks5_server_port;
        std::vector<std::string> app_names;
        Driver2SocksConfig():
            enable_ipv6(false),
            socks5_server_ip("127.0.0.1"),
            socks5_server_port(7890)
        {}
    };
}

namespace driver2socks {
    void from_json(const json & j, Driver2SocksConfig & x);
    void to_json(json & j, const Driver2SocksConfig & x);

    inline void from_json(const json & j, Driver2SocksConfig& x) {
        x.enable_ipv6 = j.at("enable_ipv6").get<bool>();
        x.socks5_server_ip = j.at("socks5server_ip").get<std::string>();
        x.socks5_server_port = j.at("socks5server_port").get<uint16_t>();
        x.app_names = j.at("app_names").get<std::vector<std::string>>();
    }

    inline void to_json(json & j, const Driver2SocksConfig & x) {
        j = json::object();
        j["enable_ipv6"] = x.enable_ipv6;
        j["socks5server_ip"] = x.socks5_server_ip;
        j["socks5server_port"] = x.socks5_server_port;
        j["app_names"] = x.app_names;
    }
}
