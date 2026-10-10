#pragma once
#include <windows.h>
#include <objbase.h>
#include <string>
#include <filesystem>
#include <vector>
#include <span>
#include <stdexcept>
#include <memory>

namespace facepass {
class Handle {
  HANDLE h_ = INVALID_HANDLE_VALUE;
public:
  Handle() = default;
  explicit Handle(HANDLE h) : h_(h) {}
  ~Handle() { reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& o) noexcept : h_(o.release()) {}
  Handle& operator=(Handle&& o) noexcept { if(this != &o) reset(o.release()); return *this; }
  HANDLE get() const { return h_; }
  explicit operator bool() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
  HANDLE release() { auto h = h_; h_ = INVALID_HANDLE_VALUE; return h; }
  void reset(HANDLE h = INVALID_HANDLE_VALUE) { if(*this) CloseHandle(h_); h_ = h; }
};
std::wstring win_error(DWORD code = GetLastError());
[[noreturn]] void fail(const char* where, DWORD code = GetLastError());
std::wstring token_sid(HANDLE token);
std::wstring current_sid();
bool is_system_sid(const std::wstring& sid);
std::filesystem::path executable_dir();
std::filesystem::path data_dir(bool service);
std::wstring pipe_name(bool demo);
std::wstring widen(const std::string&);
std::string narrow(const std::wstring&);
void random_bytes(std::span<std::uint8_t>);
std::uint64_t unix_millis();
void event_log(const std::wstring& message, WORD type = EVENTLOG_INFORMATION_TYPE);
void protect_directory(const std::filesystem::path&, bool service);
bool fresh_interactive_token(HANDLE token);
Handle reauthenticate(HWND parent);
Handle recent_session_authentication();
class Impersonation {
  bool active_ = false;
public:
  explicit Impersonation(HANDLE token);
  ~Impersonation() { if(active_) RevertToSelf(); }
  Impersonation(const Impersonation&) = delete;
};
}
