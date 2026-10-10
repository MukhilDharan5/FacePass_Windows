#pragma once
#include "platform.hpp"
#include "types.hpp"
#include <map>

namespace facepass {
inline constexpr char UnlockPackageName[] = "FacePassUnlock";
inline constexpr unsigned UnlockLifetimeSeconds = 10;
#pragma pack(push, 1)
struct UnlockTicket {
  std::uint32_t version = 0;
  std::uint32_t session = 0xffffffff;
  std::uint64_t expires = 0;
  std::array<std::uint8_t, 32> nonce{};
  wchar_t sid[192]{};
};
struct UnlockLogon {
  std::uint32_t magic = ProtocolMagic;
  std::uint32_t version = 1;
  UnlockTicket ticket{};
};
#pragma pack(pop)
bool valid_ticket(const UnlockTicket&, std::uint64_t now);
bool passwordless_enabled();
bool unlock_package_id(ULONG& id);
// Access is serialized by Controller. Tickets never survive service restart.
class UnlockGrants {
  struct Grant { UnlockTicket ticket; std::chrono::steady_clock::time_point deadline; };
  std::map<std::wstring, Grant> grants_;
public:
  UnlockTicket issue(const std::wstring&, DWORD session);
  UnlockTicket peek(const std::wstring&, DWORD session);
  bool consume(const UnlockTicket&);
  void revoke(const std::wstring& sid) { grants_.erase(sid); }
  void clear() { grants_.clear(); }
};
}
