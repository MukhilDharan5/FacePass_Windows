#include "facepass/storage.hpp"
#include <sddl.h>
#include <wincrypt.h>
#include <fstream>
#include <cstring>
#include <cmath>
namespace facepass {
namespace {
constexpr DWORD MaxFile=32768;
std::vector<std::uint8_t> crypt(std::span<const std::uint8_t> data, bool encrypt) {
  DATA_BLOB input{static_cast<DWORD>(data.size()),const_cast<BYTE*>(data.data())},out{};
  const char entropyText[]="FacePass template/config version 1";
  DATA_BLOB entropy{sizeof(entropyText),reinterpret_cast<BYTE*>(const_cast<char*>(entropyText))};
  BOOL ok=encrypt ? CryptProtectData(&input,L"FacePass encrypted data",&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out)
    : CryptUnprotectData(&input,nullptr,&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out);
  if(!ok) fail("DPAPI");
  std::vector<std::uint8_t> result(out.pbData,out.pbData+out.cbData);
  SecureZeroMemory(out.pbData,out.cbData); LocalFree(out.pbData); return result;
}
struct Wipe { std::vector<std::uint8_t>& data; ~Wipe(){SecureZeroMemory(data.data(),data.size());} };
}
Store::Store(std::filesystem::path root, bool service):root_(std::move(root)) { protect_directory(root_,service); }
std::filesystem::path Store::path(const std::wstring& sid,const wchar_t* suffix) const {
  if(sid.size()>184 || !sid.starts_with(L"S-1-") || sid.find_first_not_of(L"S-0123456789")!=std::wstring::npos) throw std::runtime_error("Invalid storage SID");
  PSID parsed=nullptr;
  if(!ConvertStringSidToSidW(sid.c_str(),&parsed)) throw std::runtime_error("Invalid Windows SID");
  bool valid=IsValidSid(parsed)!=FALSE; LocalFree(parsed); if(!valid) throw std::runtime_error("Invalid SID");
  return root_/(sid+suffix);
}
std::vector<std::uint8_t> Store::read(const std::filesystem::path& path) {
  Handle f(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
  if(!f) fail("Open encrypted data");
  BY_HANDLE_FILE_INFORMATION info{};
  if(!GetFileInformationByHandle(f.get(),&info) || info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT || info.nFileSizeHigh || info.nFileSizeLow>MaxFile || !info.nFileSizeLow) throw std::runtime_error("Invalid encrypted data file");
  std::vector<std::uint8_t> bytes(info.nFileSizeLow); DWORD read=0;
  if(!ReadFile(f.get(),bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr)||read!=bytes.size()) fail("Read encrypted data");
  return crypt(bytes,false);
}
void Store::write(const std::filesystem::path& path,std::span<const std::uint8_t> data) {
  auto bytes=crypt(data,true);
  std::array<std::uint8_t,16> nonce{}; random_bytes(nonce);
  std::wstring tail; for(auto b:nonce) { wchar_t hex[3]; swprintf_s(hex,L"%02x",b); tail+=hex; }
  auto temp=path; temp+=L"."+tail+L".tmp";
  try {
    Handle f(CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(!f) fail("Create encrypted data");
    DWORD written=0;
    if(!WriteFile(f.get(),bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)||written!=bytes.size()) fail("Write encrypted data");
    if(!FlushFileBuffers(f.get())) fail("Flush encrypted data");
    f.reset();
    if(!MoveFileExW(temp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) fail("Commit encrypted data");
  } catch(...) { DeleteFileW(temp.c_str()); throw; }
}
Config Store::config(const std::wstring& sid) {
  std::lock_guard lock(mutex_); auto f=path(sid,L".config");
  if(GetFileAttributesW(f.c_str())==INVALID_FILE_ATTRIBUTES) { if(GetLastError()==ERROR_FILE_NOT_FOUND) return {}; fail("Read configuration"); }
  auto bytes=read(f); Wipe wipe{bytes}; Config c{};
  if(bytes.size()!=sizeof(c)) throw std::runtime_error("Corrupt configuration");
  std::memcpy(&c,bytes.data(),sizeof(c)); if(!valid_config(c)) throw std::runtime_error("Invalid saved configuration"); return c;
}
void Store::config(const std::wstring& sid,const Config& c) {
  if(!valid_config(c)) throw std::runtime_error("Invalid configuration");
  std::lock_guard lock(mutex_); write(path(sid,L".config"),{reinterpret_cast<const std::uint8_t*>(&c),sizeof(c)});
}
bool Store::enrolled(const std::wstring& sid) { std::lock_guard lock(mutex_); auto attr=GetFileAttributesW(path(sid,L".face").c_str()); return attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_REPARSE_POINT); }
Template Store::load(const std::wstring& sid) {
  std::lock_guard lock(mutex_); auto bytes=read(path(sid,L".face")); Wipe wipe{bytes};
  struct Header { std::uint32_t magic,version,count,dimensions; } h{};
  if(bytes.size()<sizeof(h)) throw std::runtime_error("Corrupt template"); std::memcpy(&h,bytes.data(),sizeof(h));
  if(h.magic!=ProtocolMagic||h.version!=1||h.count!=SampleCount||h.dimensions!=EmbeddingSize||bytes.size()!=sizeof(h)+h.count*sizeof(Embedding)) throw std::runtime_error("Unsupported or corrupt template");
  Template t; t.samples.resize(h.count); std::memcpy(t.samples.data(),bytes.data()+sizeof(h),h.count*sizeof(Embedding));
  for(const auto& e:t.samples) if(cosine(e,e)<0.99f) throw std::runtime_error("Invalid embedding"); return t;
}
void Store::save(const std::wstring& sid,const Template& t) {
  if(t.samples.size()!=SampleCount) throw std::runtime_error("Enrollment requires seven samples");
  for(const auto& e:t.samples) if(cosine(e,e)<0.99f) throw std::runtime_error("Invalid embedding");
  struct Header { std::uint32_t magic,version,count,dimensions; } h{ProtocolMagic,1,SampleCount,EmbeddingSize};
  std::vector<std::uint8_t> bytes(sizeof(h)+t.samples.size()*sizeof(Embedding)); Wipe wipe{bytes};
  std::memcpy(bytes.data(),&h,sizeof(h)); std::memcpy(bytes.data()+sizeof(h),t.samples.data(),t.samples.size()*sizeof(Embedding));
  std::lock_guard lock(mutex_); write(path(sid,L".face"),bytes);
}
void Store::remove(const std::wstring& sid) {
  std::lock_guard lock(mutex_);
  if(!DeleteFileW(path(sid,L".credential").c_str())&&GetLastError()!=ERROR_FILE_NOT_FOUND) fail("Delete saved Windows password");
  if(!DeleteFileW(path(sid,L".face").c_str())&&GetLastError()!=ERROR_FILE_NOT_FOUND) fail("Delete encrypted face profile");
}
bool Store::credential_saved(const std::wstring& sid) {
  std::lock_guard lock(mutex_);auto attr=GetFileAttributesW(path(sid,L".credential").c_str());return attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_REPARSE_POINT);
}
WindowsCredential Store::credential(const std::wstring& sid) {
  std::lock_guard lock(mutex_);auto bytes=read(path(sid,L".credential"));Wipe wipe{bytes};WindowsCredential c;
  if(bytes.size()!=sizeof(c)) throw std::runtime_error("Corrupt saved Windows credential.");
  std::memcpy(&c,bytes.data(),sizeof(c));
  if(!valid_windows_credential(c) || sid!=c.sid) throw std::runtime_error("Saved Windows credential belongs to another account or is corrupt.");
  return c;
}
void Store::credential(const std::wstring& sid,const WindowsCredential& c) {
  if(!valid_windows_credential(c) || sid!=c.sid) throw std::runtime_error("Invalid or cross-account Windows credential.");
  std::lock_guard lock(mutex_);write(path(sid,L".credential"),{reinterpret_cast<const BYTE*>(&c),sizeof(c)});
}
void Store::remove_credential(const std::wstring& sid) {
  std::lock_guard lock(mutex_);if(!DeleteFileW(path(sid,L".credential").c_str())&&GetLastError()!=ERROR_FILE_NOT_FOUND) fail("Delete saved Windows password");
}
}
