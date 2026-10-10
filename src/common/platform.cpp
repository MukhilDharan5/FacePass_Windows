#include "facepass/platform.hpp"
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <ntsecapi.h>
#include <algorithm>

namespace facepass {
std::wstring win_error(DWORD code) {
  wchar_t* buffer = nullptr;
  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
    nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
  std::wstring result = buffer ? buffer : L"Windows error " + std::to_wstring(code);
  LocalFree(buffer);
  while(!result.empty() && (result.back()==L'\r'||result.back()==L'\n')) result.pop_back();
  return result;
}
[[noreturn]] void fail(const char* where, DWORD code) { throw std::runtime_error(std::string(where)+": "+narrow(win_error(code))); }
std::wstring token_sid(HANDLE token) {
  DWORD size = 0;
  GetTokenInformation(token,TokenUser,nullptr,0,&size);
  if(size == 0 || size > 65536) fail("TokenUser");
  std::vector<std::uint8_t> data(size);
  if(!GetTokenInformation(token,TokenUser,data.data(),size,&size)) fail("TokenUser");
  wchar_t* sid = nullptr;
  if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,&sid)) fail("ConvertSid");
  std::wstring result(sid); LocalFree(sid); return result;
}
std::wstring current_sid() {
  HANDLE raw = nullptr;
  if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) fail("OpenProcessToken");
  Handle token(raw); return token_sid(token.get());
}
bool is_system_sid(const std::wstring& sid) { return sid == L"S-1-5-18"; }
std::filesystem::path executable_dir() {
  std::vector<wchar_t> buf(32768);
  auto n = GetModuleFileNameW(nullptr,buf.data(),static_cast<DWORD>(buf.size()));
  if(!n || n >= buf.size()) fail("GetModuleFileName");
  return std::filesystem::path(std::wstring(buf.data(),n)).parent_path();
}
std::filesystem::path data_dir(bool service) {
  if(!service) {
    wchar_t overridePath[32768]{}; auto count=GetEnvironmentVariableW(L"FACEPASS_DEMO_DATA",overridePath,std::size(overridePath));
    if(count && count<std::size(overridePath)) {
      std::filesystem::path root(overridePath);
      if(!root.is_absolute()) throw std::runtime_error("FACEPASS_DEMO_DATA must be an absolute path");
      return root;
    }
  }
  wchar_t* path = nullptr;
  auto hr = SHGetKnownFolderPath(service ? FOLDERID_ProgramData : FOLDERID_LocalAppData,0,nullptr,&path);
  if(FAILED(hr)) fail("SHGetKnownFolderPath",static_cast<DWORD>(hr));
  std::filesystem::path result(path); CoTaskMemFree(path);
  return result / (service ? L"FacePass" : L"FacePassDemo");
}
std::wstring pipe_name(bool demo) { return L"\\\\.\\pipe\\FacePass.v2" + (demo ? L".Demo."+current_sid() : L""); }
std::wstring widen(const std::string& s) {
  if(s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
  if(!n) return L"Unrecognized error text";
  std::wstring out(n,L'\0'); MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n); return out;
}
std::string narrow(const std::wstring& s) {
  if(s.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
  std::string out(n,'\0'); WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr); return out;
}
void random_bytes(std::span<std::uint8_t> bytes) {
  if(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    throw std::runtime_error("CNG random generation failed");
}
std::uint64_t unix_millis() {
  FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER value{}; value.LowPart=ft.dwLowDateTime; value.HighPart=ft.dwHighDateTime;
  return (value.QuadPart-116444736000000000ULL)/10000;
}
void event_log(const std::wstring& text, WORD type) {
  HANDLE source = RegisterEventSourceW(nullptr,L"FacePass");
  if(source) { const wchar_t* p = text.c_str(); ReportEventW(source,type,0,1,nullptr,1,0,&p,nullptr); DeregisterEventSource(source); }
}
void protect_directory(const std::filesystem::path& path, bool service) {
  std::filesystem::create_directories(path);
  if(GetFileAttributesW(path.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT) throw std::runtime_error("Data directory is a reparse point");
  std::wstring owner = current_sid();
  if(service) {
    DWORD size=SECURITY_MAX_SID_SIZE, domainSize=256; SID_NAME_USE use{};
    std::vector<std::uint8_t> sid(size); wchar_t domain[256]{};
    if(!LookupAccountNameW(nullptr,L"NT SERVICE\\FacePassService",sid.data(),&size,domain,&domainSize,&use)) fail("Resolve service SID");
    wchar_t* value=nullptr;
    if(!ConvertSidToStringSidW(sid.data(),&value)) fail("Service SID");
    owner=value; LocalFree(value);
  }
  auto sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+owner+L")";
  PSECURITY_DESCRIPTOR desc=nullptr;
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&desc,nullptr)) fail("Directory ACL");
  BOOL present=FALSE,defaulted=FALSE; PACL acl=nullptr;
  GetSecurityDescriptorDacl(desc,&present,&acl,&defaulted);
  auto error=SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,acl,nullptr);
  LocalFree(desc); if(error != ERROR_SUCCESS) fail("Set directory ACL",error);
}
bool fresh_interactive_token(HANDLE token) {
  TOKEN_STATISTICS stats{}; DWORD length=0;
  if(!GetTokenInformation(token,TokenStatistics,&stats,sizeof(stats),&length)) return false;
  PSECURITY_LOGON_SESSION_DATA data=nullptr;
  if(LsaGetLogonSessionData(&stats.AuthenticationId,&data)!=0 || !data) return false;
  FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER now{}; now.LowPart=ft.dwLowDateTime; now.HighPart=ft.dwHighDateTime;
  auto time = static_cast<ULONGLONG>(data->LogonTime.QuadPart);
  bool ok = data->LogonType == Interactive && time > 0 && now.QuadPart >= time && now.QuadPart-time <= 120ULL*10000000;
  LsaFreeReturnBuffer(data); return ok;
}
Impersonation::Impersonation(HANDLE token) {
  if(token) { if(!ImpersonateLoggedOnUser(token)) fail("Impersonate authenticated user"); active_=true; }
}
}
