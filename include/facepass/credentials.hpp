#pragma once
#include "platform.hpp"
#include <array>
#include <cstdint>

namespace facepass {
// Fixed-size, bounded IPC/storage record. Every owned copy erases its secret.
struct WindowsCredential {
  std::uint32_t version = 0;
  wchar_t sid[192]{};
  wchar_t username[513]{};
  wchar_t password[513]{};
  ~WindowsCredential() { SecureZeroMemory(password,sizeof(password)); }
};
struct VerifiedCredential {
  Handle token;
  WindowsCredential credential;
};
bool valid_windows_credential(const WindowsCredential&);
std::wstring microsoft_account_username(const std::wstring& username,const std::wstring& domain={});
Handle verify_windows_credential(const WindowsCredential&);
VerifiedCredential prompt_windows_credential(HWND parent, bool saveForUnlock);
bool password_unlock_enabled();
bool negotiate_package_id(ULONG& id);
// Called in LogonUI, so protected online credentials belong to its logon session.
std::vector<BYTE> pack_windows_credential(const WindowsCredential&);
}
