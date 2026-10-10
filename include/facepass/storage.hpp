#pragma once
#include "types.hpp"
#include "platform.hpp"
#include "credentials.hpp"
#include <mutex>
namespace facepass {
class Store {
  std::filesystem::path root_;
  std::mutex mutex_;
  std::filesystem::path path(const std::wstring&, const wchar_t*) const;
  std::vector<std::uint8_t> read(const std::filesystem::path&);
  void write(const std::filesystem::path&, std::span<const std::uint8_t>);
public:
  Store(std::filesystem::path root, bool service);
  Config config(const std::wstring& sid);
  void config(const std::wstring& sid, const Config&);
  bool enrolled(const std::wstring& sid);
  Template load(const std::wstring& sid);
  void save(const std::wstring& sid, const Template&);
  void remove(const std::wstring& sid);
  bool credential_saved(const std::wstring& sid);
  WindowsCredential credential(const std::wstring& sid);
  void credential(const std::wstring& sid,const WindowsCredential&);
  void remove_credential(const std::wstring& sid);
};
}
