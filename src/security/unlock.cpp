#include "facepass/unlock.hpp"
#include <ntsecapi.h>
#include <sddl.h>
#include <algorithm>
#include <cstring>

namespace facepass {
bool valid_ticket(const UnlockTicket& t, std::uint64_t now) {
  if(t.version != 1 || t.session == 0xffffffff || t.expires < now || t.expires - now > UnlockLifetimeSeconds*1000
      || std::find(std::begin(t.sid), std::end(t.sid), L'\0') == std::end(t.sid)
      || std::all_of(t.nonce.begin(), t.nonce.end(), [](auto b){return b == 0;})) return false;
  PSID sid = nullptr;
  if(!ConvertStringSidToSidW(t.sid, &sid)) return false;
  bool ok = IsValidSid(sid) && !IsWellKnownSid(sid, WinLocalSystemSid)
      && !IsWellKnownSid(sid, WinLocalServiceSid) && !IsWellKnownSid(sid, WinNetworkServiceSid);
  LocalFree(sid); return ok;
}
bool passwordless_enabled() {
  DWORD enabled = 0, size = sizeof(enabled);
  return RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\FacePass", L"PasswordlessUnlock", RRF_RT_REG_DWORD,
      nullptr, &enabled, &size) == ERROR_SUCCESS && enabled == 1;
}
bool unlock_package_id(ULONG& id) {
  id = 0; HANDLE lsa = nullptr;
  if(LsaConnectUntrusted(&lsa) < 0) return false;
  LSA_STRING name{}; name.Buffer = const_cast<char*>(UnlockPackageName);
  name.Length = static_cast<USHORT>(sizeof(UnlockPackageName)-1); name.MaximumLength = sizeof(UnlockPackageName);
  auto status = LsaLookupAuthenticationPackage(lsa, &name, &id);
  LsaDeregisterLogonProcess(lsa); return status >= 0;
}
UnlockTicket UnlockGrants::issue(const std::wstring& sid, DWORD session) {
  UnlockTicket ticket; ticket.version = 1; ticket.session = session;
  ticket.expires = unix_millis() + UnlockLifetimeSeconds*1000; random_bytes(ticket.nonce);
  if(sid.size() >= std::size(ticket.sid)) throw std::runtime_error("Unlock SID is too long");
  wcscpy_s(ticket.sid, sid.c_str());
  if(!valid_ticket(ticket, unix_millis())) throw std::runtime_error("Invalid unlock identity");
  grants_[sid] = {ticket, std::chrono::steady_clock::now()+std::chrono::seconds(UnlockLifetimeSeconds)};
  return ticket;
}
UnlockTicket UnlockGrants::peek(const std::wstring& sid, DWORD session) {
  auto it = grants_.find(sid);
  if(it == grants_.end()) return {};
  if(std::chrono::steady_clock::now() >= it->second.deadline || !valid_ticket(it->second.ticket, unix_millis())) {
    grants_.erase(it); return {};
  }
  return it->second.ticket.session == session ? it->second.ticket : UnlockTicket{};
}
bool UnlockGrants::consume(const UnlockTicket& ticket) {
  if(!valid_ticket(ticket, unix_millis())) return false;
  auto saved = peek(ticket.sid, ticket.session);
  if(saved.version != 1 || std::memcmp(&ticket, &saved, sizeof(ticket)) != 0) return false;
  grants_.erase(ticket.sid); return true;
}
}
