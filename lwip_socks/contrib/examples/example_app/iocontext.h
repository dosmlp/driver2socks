#pragma once
#include <asio.hpp>

class IoContext
{
	asio::io_context io_context_;
	asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
	std::thread thread_io_;

	static IoContext* self_;
	static std::mutex mutex_;
	IoContext():
		io_context_(1),
		work_guard_(asio::make_work_guard(io_context_))
	{
		thread_io_ = std::thread(std::bind(&IoContext::run, this));
	}

	asio::io_context& getIo()
	{
		return io_context_;
	}
	void run()
	{
		io_context_.run();
	}
public:
	~IoContext()
	{
		io_context_.stop();
		thread_io_.join();
	}
	static IoContext* Instance()
	{
		if (self_ != nullptr) {
			return self_;
		}
		mutex_.lock();
		if (self_ == nullptr) {
			self_ = new IoContext();
		}
		mutex_.unlock();
		return self_;
	}
	static asio::io_context& getIoContext()
	{
		return Instance()->getIo();
	}
};