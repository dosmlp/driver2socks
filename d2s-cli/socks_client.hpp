#ifndef SOCKS_CLIENT_HPP
#define SOCKS_CLIENT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)
#include <memory>
#include <lwip/tcp.h>

#include "io.hpp"
#include "async_simple/coro/Lazy.h"
#include "asio_coro_util.hpp"
#include "iocontext.h"
#include "ring_buf.hpp"
#include "netpacket_pool.h"

namespace driver2socks {

	inline bool parse_udp_proxy_header(const void* buf, std::size_t len,
		asio::ip::tcp::endpoint& src, asio::ip::tcp::endpoint& dst, uint16_t& payload_len)
	{
		const uint8_t* p = (const uint8_t*)buf;
		if (len < 16)
			return false;

		read_int8(p);
		auto local_ip = read_uint32(p);
		auto local_port = read_uint16(p);
		src.address(asio::ip::address_v4(local_ip));
		src.port(local_port);

		read_int8(p);
		auto remote_ip = read_uint32(p);
		auto remote_port = read_uint16(p);
		dst.address(asio::ip::address_v4(remote_ip));
		dst.port(remote_port);

		payload_len = read_uint16(p);

		return true;
	}

	inline std::string make_udp_proxy_header(
		const asio::ip::tcp::endpoint& src, const asio::ip::tcp::endpoint& dst, const uint16_t& payload_len)
	{
		std::string response;
		response.resize(payload_len + 16);
		char* resp = (char*)response.data();

		// 添加头信息.
		write_uint8(1, resp);	// atyp.
		write_uint32(src.address().to_v4().to_uint(), resp);	// ip.
		write_uint16(src.port(), resp);	// port.
		write_uint8(1, resp);	// atyp.
		write_uint32(dst.address().to_v4().to_uint(), resp);	// ip.
		write_uint16(dst.port(), resp);	// port.
		write_uint16(payload_len, resp); // payload_len.

		return response;
	}


	//////////////////////////////////////////////////////////////////////////

	class error_category_impl;

	template<class error_category>
	const asio::error_category& error_category_single()
	{
		static error_category error_category_instance;
		return reinterpret_cast<const asio::error_category&>(error_category_instance);
	}

	inline const asio::error_category& error_category()
	{
		return error_category_single<driver2socks::error_category_impl>();
	}

	namespace errc {
		enum errc_t
		{
			/// SOCKS unsupported version.
			socks_unsupported_version = 1000,

			/// SOCKS username required.
			socks_username_required,

			/// SOCKS unsupported authentication version.
			socks_unsupported_authentication_version,

			/// SOCKS authentication error.
			socks_authentication_error,

			/// SOCKS general failure.
			socks_general_failure,

			/// SOCKS command not supported.
			socks_command_not_supported,

			/// SOCKS no identd running.
			socks_no_identd,

			/// SOCKS no identd running.
			socks_identd_error,

			/// request rejected or failed.
			socks_request_rejected_or_failed,

			/// request rejected becasue SOCKS server cannot connect to identd on the client.
			socks_request_rejected_cannot_connect,

			/// request rejected because the client program and identd report different user - ids
			socks_request_rejected_incorrect_userid,

			socks_connect_proxy_fail,
		};

		inline asio::error_code make_error_code(errc_t e)
		{
			return asio::error_code(static_cast<int>(e), driver2socks::error_category());
		}
	}

	class error_category_impl
		: public asio::error_category
	{
		virtual const char* name() const noexcept
		{
			return "SOCKS";
		}

		virtual std::string message(int e) const
		{
			switch (e)
			{
			case errc::socks_unsupported_version:
				return "SOCKS unsupported version";
			case errc::socks_username_required:
				return "SOCKS username required";
			case errc::socks_unsupported_authentication_version:
				return "SOCKS unsupported authentication version";
			case errc::socks_authentication_error:
				return "SOCKS authentication error";
			case errc::socks_general_failure:
				return "SOCKS general failure";
			case errc::socks_command_not_supported:
				return "SOCKS command not supported";
			case errc::socks_no_identd:
				return "SOCKS no identd running";
			case errc::socks_identd_error:
				return "SOCKS identd error";
			case errc::socks_request_rejected_or_failed:
				return "request rejected or failed";
			case errc::socks_request_rejected_cannot_connect:
				return "request rejected becasue SOCKS server cannot connect to identd on the client";
			case errc::socks_request_rejected_incorrect_userid:
				return "request rejected because the client program and identd report different user";
			case errc::socks_connect_proxy_fail:
				return "proxy connect fail";
			default:
				return "Unknown PROXY error";
			}
		}
	};
}

namespace std {

	template <>
	struct is_error_code_enum<driver2socks::errc::errc_t>
	{
		static const bool value = true;
	};

} // namespace system


namespace driver2socks {

	//////////////////////////////////////////////////////////////////////////

	// 解析uri格式
	// scheme:[//[user[:password]@]host[:port]][/path][?query][#fragment]

	struct socks_address
	{
		typedef std::shared_ptr<socks_address> Ptr;
		std::string host;
		std::string port;
		std::string path;
		std::string query;
		std::string fragment;
		std::string username;
		std::string password;

		// proxy_address为代理服务器连接的对象,
		// 如果是ip, proxy_hostname则应该为false.
		// 如果是域名, proxy_hostname应该为true.
		std::string proxy_address;

		// 代理服务器连接的目标端口.
		std::string proxy_port;

		// 控制代理服务器是否解析域名.
		bool proxy_hostname;

		// 打开udp转发.
		bool udp_associate;
	};

	class socks_client : public std::enable_shared_from_this<socks_client>
	{
	public:
		tcp_pcb* lwip_tcp_pcb_ = nullptr;
		enum {
			SOCKS_VERSION_4 = 4,
			SOCKS_VERSION_5 = 5
		};
		enum {
			SOCKS5_AUTH_NONE = 0x00,
			SOCKS5_AUTH = 0x02,
			SOCKS5_AUTH_UNACCEPTABLE = 0xFF
		};
		enum {
			SOCKS_CMD_CONNECT = 0x01,
			SOCKS_CMD_BIND = 0x02,
			SOCKS5_CMD_UDP = 0x03
		};
		enum {
			SOCKS5_ATYP_IPV4 = 0x01,
			SOCKS5_ATYP_DOMAINNAME = 0x03,
			SOCKS5_ATYP_IPV6 = 0x04
		};
		enum {
			SOCKS5_SUCCEEDED = 0x00,
			SOCKS5_GENERAL_SOCKS_SERVER_FAILURE,
			SOCKS5_CONNECTION_NOT_ALLOWED_BY_RULESET,
			SOCKS5_NETWORK_UNREACHABLE,
			SOCKS5_CONNECTION_REFUSED,
			SOCKS5_TTL_EXPIRED,
			SOCKS5_COMMAND_NOT_SUPPORTED,
			SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,
			SOCKS5_UNASSIGNED
		};
		enum {
			SOCKS4_REQUEST_GRANTED = 90,
			SOCKS4_REQUEST_REJECTED_OR_FAILED,
			SOCKS4_CANNOT_CONNECT_TARGET_SERVER,
			SOCKS4_REQUEST_REJECTED_USER_NO_ALLOW,
		};

		enum {
			MAX_RECV_BUFFER_SIZE = 768,	// 最大udp接收缓冲大小.
			MAX_SEND_BUFFER_SIZE = 768	// 最大udp发送缓冲大小.
		};

	public:
		explicit socks_client(asio::io_context& io):m_socket(io)
		{
		}
		~socks_client()
		{
			m_socket.close();
			lwip_tcp_pcb_ = nullptr;
		}

		bool sendData(uint8_t* data, uint32_t len)
		{
			bool ret = buf_send_.Write(data, len);
			startSend();
			return ret;
		}
		void closeSocket()
		{
			m_socket.close();
		}

		void startSend()
		{
			if (!do_proxy_done) {
				return;
			}
			bool expectation = false;
			if (!is_writing_.compare_exchange_weak(expectation,true)) {
				return;
			}
			int len = buf_send_.GetAvailable();
			if (len > 1024) {
				len = 1024;
			}
			if (len <= 0) {
				is_writing_.store(false);
				return;
			}
            std::shared_ptr<NetPacket> bf(_NetPacketPool->getPacket(len), [](NetPacket* p) { _NetPacketPool->freePacket(p); });

            buf_send_.Read(bf->data, len);
			auto self = shared_from_this();
            asio::async_write(m_socket, asio::buffer(bf->data,len), asio::transfer_exactly(len), [this,self, bf](asio::error_code ec, size_t size) {
				is_writing_.store(false);
				if (ec) {
					std::cout << "asio::async_write error:" << ec.message() << "\n";
					self->m_socket.close();
					//handler(ec, std::shared_ptr<void>(nullptr), 0, self->lwip_tcp_pcb_);
				} else {
					if (buf_send_.GetAvailable() > 0) self->startSend();
				}
			});
		}
		template <typename Handler>
		void startRecv(Handler read_callback)
		{
            std::shared_ptr<NetPacket> bf(_NetPacketPool->getPacket(NETPACKET_DATA_SIZE), [](NetPacket* p) {_NetPacketPool->freePacket(p); });
			auto self = shared_from_this();
			m_socket.async_read_some(asio::buffer(bf->data, bf->capacity_size), 
				[self,bf,read_callback,this](asio::error_code ec, size_t size) {
				if (ec) {
					std::cout << "socket async_read_some error:" << ec.message() << "\n";
					self->m_socket.close();
					read_callback(ec, std::shared_ptr<NetPacket>(nullptr), 0, self->lwip_tcp_pcb_);
				} else {
					bf->data_len = size;
					read_callback(ec, bf, size, self->lwip_tcp_pcb_);
					self->startRecv(read_callback);
				}
			});
		}

		template <typename Handler, typename HandlerRead>
		void start_socks( std::string host, uint16_t port, std::string proxy_address, uint16_t proxy_port,HandlerRead read, Handler handler)
		{
			socks_address::Ptr socks_addr = std::make_shared<socks_address>();
			socks_addr->host = host;
			socks_addr->port = std::to_string(port);
			socks_addr->proxy_hostname = false;
			socks_addr->udp_associate = false;
			socks_addr->proxy_address = proxy_address;
			socks_addr->proxy_port = std::to_string(proxy_port);

			auto self = shared_from_this();
			/*
			m_socket.async_connect(asio::ip::tcp::endpoint(asio::ip::make_address(proxy_address), proxy_port),
				[self,this,read](asio::error_code ec) {
				if (ec) {
					std::cout << "error connect to proxy\n";
				} else {
					do_proxy_done = true;
					startRecv(read);
					startSend();
				}
			});
			*/
			async_do_proxy(socks_addr,handler).start([read,this,self](async_simple::Try<void> Result) {
					if (Result.hasError()) {
						std::cout << "Error Happened in async_do_proxy.\n";
					} else {
						std::cout << "async_do_proxy completed successfully.\n";
						do_proxy_done = true;
						startRecv(read);
						startSend();
					}
				});
			
		}

		template <typename Handler>
		async_simple::coro::Lazy<bool> async_do_proxy(socks_address::Ptr content,Handler handler)
		{
			auto ec = co_await async_connect(IoContext::getIoContext(), m_socket, content->host, content->port);
			//auto ec = co_await async_connect(IoContext::getIoContext(), m_socket, content->proxy_address, content->proxy_port);
			if (ec) {
				std::cout << "Connect error: " << ec.message() << '\n';
				handler(driver2socks::errc::socks_connect_proxy_fail);
				co_return;
			}
			m_socks_address = content;
			m_address = content->proxy_address;
			m_port = content->proxy_port;

			co_await do_socks5<Handler>(handler);

			co_return true;
		}

		asio::ip::udp::endpoint udp_endpoint()
		{
			asio::ip::udp::endpoint endp;
			endp.address(m_remote_endp.address());
			endp.port(m_remote_endp.port());
			return endp;
		}

	private:
		template <typename Handler>
		async_simple::coro::Lazy<void> do_socks5(Handler handler)
		{
			std::size_t bytes_to_write = m_socks_address->username.empty() ? 3 : 4;
			asio::streambuf request;
			asio::mutable_buffer b = request.prepare(bytes_to_write);
			char* p = asio::buffer_cast<char*>(b);

			write_uint8(5, p); // SOCKS VERSION 5.
			if (m_socks_address->username.empty())
			{
				write_uint8(1, p); // 1 authentication method (no auth)
				write_uint8(0, p); // no authentication
			}
			else
			{
				write_uint8(2, p); // 2 authentication methods
				write_uint8(0, p); // no authentication
				write_uint8(2, p); // username/password
			}
			
			request.commit(bytes_to_write);
			//发起握手请求
			auto [ec1, wsize] = co_await ::async_write(m_socket, request.data(), asio::transfer_exactly(bytes_to_write));
			
			if (ec1)
			{
				handler(ec1);
				co_return;
			}

			asio::streambuf response;
			auto [ec, rsize] = co_await ::async_read(m_socket, response,asio::transfer_exactly(2));
			if (ec)
			{
				handler(ec);
				co_return;
			}
			
			//处理代理服务器返回的握手响应
			int method;
			bool authed = false;

			{
				int version;

				asio::const_buffer b = response.data();
				const char* p = asio::buffer_cast<const char*>(b);
				version = read_uint8(p);
				method = read_uint8(p);
				if (version != 5)	// 版本不等于5, 不支持socks5.
				{
					ec = driver2socks::errc::socks_unsupported_version;
					handler(ec);
					co_return;
				}
			}
			//如果代理服务需要密码验证
			if (method == 2)
			{
				if (m_socks_address->username.empty())
				{
					ec = driver2socks::errc::socks_username_required;
					handler(ec);
					co_return;
				}

				// start sub-negotiation.
				request.consume(request.size());

				std::size_t bytes_to_write = m_socks_address->username.size() + m_socks_address->password.size() + 3;
				asio::mutable_buffer mb = request.prepare(bytes_to_write);
				char* mp = asio::buffer_cast<char*>(mb);

				write_uint8(1, mp);
				write_uint8(static_cast<int8_t>(m_socks_address->username.size()), mp);
				write_string(m_socks_address->username, mp);
				write_uint8(static_cast<int8_t>(m_socks_address->password.size()), mp);
				write_string(m_socks_address->password, mp);
				request.commit(bytes_to_write);

				int len = 0;
				// 发送用户密码信息.
				auto [ec, wsize] = co_await ::async_write(m_socket, request.data(), asio::transfer_exactly(bytes_to_write));
				if (ec)
				{
					handler(ec);
					co_return;
				}
				//BOOST_ASSERT("len == bytes_to_write" && len == bytes_to_write);

				// 读取状态.
				response.consume(response.size());
				auto [ec2, rsize] = co_await ::async_read(m_socket, response,asio::transfer_exactly(2));
				if (ec2)
				{
					handler(ec2);
					co_return;
				}
				//BOOST_ASSERT("len == 2" && len == 2);

				// 读取版本状态.
				asio::const_buffer cb = response.data();
				const char* cp = asio::buffer_cast<const char*>(cb);

				int version = read_uint8(cp);
				int status = read_uint8(cp);

				// 不支持的认证版本.
				if (version != 1)
				{
					ec = errc::socks_unsupported_authentication_version;
					handler(ec);
					co_return;
				}

				// 认证错误.
				if (status != 0)
				{
					ec = errc::socks_authentication_error;
					handler(ec);
					co_return;
				}

				authed = true;
			}//密码认证结束

			//不需要认证
			if (method == 0 || authed)
			{
				request.consume(request.size());
				std::size_t bytes_to_write = 7 + m_address.size();
				asio::mutable_buffer mb = request.prepare(std::max<std::size_t>(bytes_to_write, 22));
				char* wp = asio::buffer_cast<char*>(mb);
				
				// 发送socks5连接命令.
				write_uint8(5, wp); // SOCKS VERSION 5.
									// CONNECT/UDP command.
				write_uint8(m_socks_address->udp_associate ? SOCKS5_CMD_UDP : SOCKS_CMD_CONNECT, wp);
				write_uint8(0, wp); // reserved.

				if (m_socks_address->proxy_hostname)
				{
					write_uint8(3, wp); // atyp, domain name.
					//BOOST_ASSERT(m_address.size() <= 255);
					write_uint8(static_cast<int8_t>(m_address.size()), wp);	// domainname size.
					std::copy(m_address.begin(), m_address.end(), wp);		// domainname.
					wp += m_address.size();
					write_uint16(atoi(m_port.c_str()), wp);					// port.
				}
				else
				{
					auto endp = asio::ip::address::from_string(m_address);
					if (endp.is_v4())
					{
						write_uint8(1, wp); // ipv4.
						write_uint32(endp.to_v4().to_ulong(), wp);
						write_uint16(atoi(m_port.c_str()), wp);
						bytes_to_write = 10;
					}
					else
					{
						write_uint8(4, wp); // ipv6.
						auto bytes = endp.to_v6().to_bytes();
						std::copy(bytes.begin(), bytes.end(), wp);
						wp += 16;
						write_uint16(atoi(m_port.c_str()), wp);
						bytes_to_write = 22;
					}
				}

				std::size_t len = 0;
				request.commit(bytes_to_write);
				auto [ec, wsize] = co_await ::async_write(m_socket, request.data(), asio::transfer_exactly(bytes_to_write));
				if (ec)
				{
					handler(ec);
					co_return;
				}
				//BOOST_ASSERT("len == bytes_to_write" && len == bytes_to_write);
				
				//读取连接响应
				std::size_t bytes_to_read = 10;
				response.consume(response.size());
				auto [ec3, rsize] = co_await ::async_read(m_socket, response, asio::transfer_exactly(bytes_to_read));
				if (ec3)
				{
					handler(ec3);
					co_return;
				}
				//BOOST_ASSERT("len == bytes_to_read" && len == bytes_to_read);
				asio::const_buffer cb = response.data();
				const char* rp = asio::buffer_cast<const char*>(cb);
				int version = read_uint8(rp);
				int resp = read_uint8(rp);
				read_uint8(rp);	// skip RSV.
				int atyp = read_uint8(rp);

				if (atyp == 1) // ADDR.PORT
				{
					m_remote_endp.address(asio::ip::address_v4(read_uint32(rp)));
					m_remote_endp.port(read_uint16(rp));

					if (m_socks_address->udp_associate)
					{
						// 更新远程地址, 后面用于udp传输.
						m_remote_endp.address(m_socket.remote_endpoint(ec).address());
						//LOG_DBG << "* SOCKS udp server: " << m_remote_endp.address().to_string()
						//	<< ":" << m_remote_endp.port();
						// 在这之后，保持这个tcp连接直到udp代理也不需要了.
					}
// 					else
// 					{
// 						LOG_DBG << "* SOCKS remote host: " << m_remote_endp.address().to_string()
// 							<< ":" << m_remote_endp.port();
// 					}

					//response.consume(len);
					//BOOST_ASSERT("response.size() == 0" && response.size() == 0);
				}
				else if (atyp == 3) // DOMAIN
				{
					auto domain_length = read_uint8(rp);

					auto [ec, rsize] = co_await ::async_read(m_socket, response, asio::transfer_exactly(domain_length - 3));
					if (ec)
					{
						handler(ec);
						co_return;
					}
					//BOOST_ASSERT("len == domain_length - 3" && len == domain_length - 3);

					asio::const_buffer cb = response.data();
					rp = asio::buffer_cast<const char*>(cb) + 5;

					std::string domain;
					for (int i = 0; i < domain_length; i++)
						domain.push_back(read_uint8(rp));
					auto port = read_uint16(rp);

					//LOG_DBG << "* SOCKS remote host: " << domain << ":" << port;
					response.consume(len + 10);
					//BOOST_ASSERT("response.size() == 0" && response.size() == 0);
				}
				else
				{
					ec = errc::socks_general_failure;
					handler(ec);
					co_return;
				}

				if (version != 5)
				{
					ec = errc::socks_unsupported_version;
					handler(ec);
					co_return;
				}

				if (resp != 0)
				{
					ec = errc::socks_general_failure;
					// 得到更详细的错误信息.
					switch (resp)
					{
					case 2: ec = asio::error::no_permission; break;
					case 3: ec = asio::error::network_unreachable; break;
					case 4: ec = asio::error::host_unreachable; break;
					case 5: ec = asio::error::connection_refused; break;
					case 6: ec = asio::error::timed_out; break;
					case 7: ec = errc::socks_command_not_supported; break;
					case 8: ec = asio::error::address_family_not_supported; break;
					}

					handler(ec);
					co_return;
				}
				
				ec = asio::error_code();	// 没有发生错误, 返回.
				
				handler(ec);
				co_return;
			}

			ec = asio::error::address_family_not_supported;
			handler(ec);
			co_return;
		}

	private:
		volatile bool do_proxy_done = false;
		std::atomic_bool is_writing_ = false;
		asio::ip::tcp::socket m_socket;
		socks_address::Ptr m_socks_address;
		std::string m_address;
		std::string m_port;
		asio::ip::tcp::endpoint m_remote_endp;

		lockfree::spsc::RingBuf<uint8_t, 4096*10> buf_send_;
	};
}

#endif // SOCKS_CLIENT_HPP
