#include "facepass/credentials.hpp"
#include <wincred.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <algorithm>

namespace facepass {
namespace {
template<size_t N> bool terminated(const wchar_t (&text)[N]) {
  return std::find(std::begin(text),std::end(text),L'\0')!=std::end(text);
}
}
std::wstring microsoft_account_username(const std::wstring& username,const std::wstring& domain) {
  auto invalid=[](){throw std::runtime_error("Enter your Microsoft-account email address, or MicrosoftAccount\\your-email.");};
  if(username.empty() || username.size()>512 || domain.size()>512
      || username.find(L'\0')!=std::wstring::npos || domain.find(L'\0')!=std::wstring::npos) invalid();
  if(!domain.empty() && _wcsicmp(domain.c_str(),L"MicrosoftAccount")!=0) invalid();
  auto identity=username;
  auto slash=username.find(L'\\');
  if(slash!=std::wstring::npos) {
    if(_wcsicmp(username.substr(0,slash).c_str(),L"MicrosoftAccount")!=0) invalid();
    identity=username.substr(slash+1);
  } else if(domain.empty()) {
    auto at=username.find(L'@');
    if(at==std::wstring::npos || at==0 || at+1==username.size()) invalid();
  }
  if(identity.empty() || identity.find(L'\\')!=std::wstring::npos) invalid();
  auto qualified=std::wstring(L"MicrosoftAccount\\")+identity;
  if(qualified.size()>512) invalid();
  return qualified;
}
bool valid_windows_credential(const WindowsCredential& c) {
  if(c.version!=1 || !terminated(c.sid) || !terminated(c.username) || !terminated(c.password)
      || !c.password[0] || !c.sid[0]) return false;
  // This backend deliberately targets the user's Microsoft-connected account.
  constexpr wchar_t prefix[]=L"MicrosoftAccount\\";
  if(_wcsnicmp(c.username,prefix,std::size(prefix)-1)!=0 || !c.username[std::size(prefix)-1]) return false;
  PSID sid=nullptr; if(!ConvertStringSidToSidW(c.sid,&sid)) return false;
  bool ok=IsValidSid(sid) && !IsWellKnownSid(sid,WinLocalSystemSid)
      && !IsWellKnownSid(sid,WinLocalServiceSid) && !IsWellKnownSid(sid,WinNetworkServiceSid);
  LocalFree(sid); return ok;
}
Handle verify_windows_credential(const WindowsCredential& c) {
  if(!valid_windows_credential(c)) throw std::runtime_error("Use MicrosoftAccount\\your-email and that account's password, not a PIN.");
  HANDLE raw=nullptr;
  auto username=c.username+std::size(L"MicrosoftAccount\\")-1;
  if(!LogonUserW(username,L"MicrosoftAccount",c.password,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&raw)) fail("Verify Microsoft account password");
  Handle token(raw);
  if(token_sid(token.get())!=c.sid) throw std::runtime_error("The password must belong to this Windows account.");
  return token;
}
VerifiedCredential prompt_windows_credential(HWND parent,bool saveForUnlock) {
  CREDUI_INFOW ui{}; ui.cbSize=sizeof(ui); ui.hwndParent=parent;
  ui.pszCaptionText=saveForUnlock?L"FacePass - save Windows password":L"FacePass enrollment";
  ui.pszMessageText=saveForUnlock
    ? L"Save your Microsoft-account password encrypted on this laptop for face unlock. Enter your Microsoft-account email address and password, not your PIN. MicrosoftAccount\\your-email also works."
    : L"Verify your Windows account before enrolling. Enter its password, not your Windows Hello PIN. Credentials are discarded immediately.";
  ULONG package=0;void* credentials=nullptr;ULONG size=0;BOOL save=FALSE;
  auto error=CredUIPromptForWindowsCredentialsW(&ui,0,&package,nullptr,0,&credentials,&size,&save,CREDUIWIN_GENERIC);
  if(error!=ERROR_SUCCESS) fail("Windows account verification",error);
  struct Secret {void* p;ULONG size;~Secret(){if(p){SecureZeroMemory(p,size);CoTaskMemFree(p);}}} secret{credentials,size};
  std::array<wchar_t,513> user{},domain{},password{};
  struct Wipe {std::array<wchar_t,513>& value;~Wipe(){SecureZeroMemory(value.data(),sizeof(value));}} wipe{password};
  DWORD userSize=static_cast<DWORD>(user.size()),domainSize=static_cast<DWORD>(domain.size()),passwordSize=static_cast<DWORD>(password.size());
  if(!CredUnPackAuthenticationBufferW(0,credentials,size,user.data(),&userSize,domain.data(),&domainSize,password.data(),&passwordSize)) fail("Unpack Windows verification");
  VerifiedCredential result;
  if(saveForUnlock) {
    // CredUI GENERIC leaves a bare email without a domain. Route it explicitly
    // to MicrosoftAccount before Windows verification, never to a local/AD UPN.
    auto qualified=microsoft_account_username(user.data(),domain.data());
    result.credential.version=1;
    wcscpy_s(result.credential.sid,current_sid().c_str());
    wcscpy_s(result.credential.username,qualified.c_str());
    wcscpy_s(result.credential.password,password.data());
    result.token=verify_windows_credential(result.credential);
  } else {
    HANDLE raw=nullptr;
    if(!LogonUserW(user.data(),domain[0]?domain.data():nullptr,password.data(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&raw)) fail("Verify Windows account password");
    result.token.reset(raw);
    if(token_sid(result.token.get())!=current_sid()) throw std::runtime_error("Verify the currently signed-in Windows account.");
  }
  if(!fresh_interactive_token(result.token.get())) throw std::runtime_error("Windows did not supply a fresh interactive authentication token.");
  return result;
}
bool password_unlock_enabled() {
  DWORD value=0,size=sizeof(value);
  return RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\FacePass",L"PasswordBackedUnlock",RRF_RT_REG_DWORD,nullptr,&value,&size)==ERROR_SUCCESS && value==1;
}
bool negotiate_package_id(ULONG& id) {
  id=0;HANDLE lsa=nullptr;if(LsaConnectUntrusted(&lsa)<0) return false;
  char text[]="Negotiate";LSA_STRING name{};name.Buffer=text;name.Length=sizeof(text)-1;name.MaximumLength=sizeof(text);
  auto status=LsaLookupAuthenticationPackage(lsa,&name,&id);LsaDeregisterLogonProcess(lsa);return status>=0;
}
std::vector<BYTE> pack_windows_credential(const WindowsCredential& c) {
  if(!valid_windows_credential(c)) throw std::runtime_error("Invalid Windows credential.");
  DWORD bytes=0;constexpr DWORD flags=CRED_PACK_PROTECTED_CREDENTIALS|CRED_PACK_ID_PROVIDER_CREDENTIALS;
  if(CredPackAuthenticationBufferW(flags,const_cast<wchar_t*>(c.username),const_cast<wchar_t*>(c.password),nullptr,&bytes)
      || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || !bytes || bytes>16384) throw std::runtime_error("Cannot size the Windows identity credential.");
  std::vector<BYTE> result(bytes);
  if(!CredPackAuthenticationBufferW(flags,const_cast<wchar_t*>(c.username),const_cast<wchar_t*>(c.password),result.data(),&bytes)) {
    SecureZeroMemory(result.data(),result.size());fail("Package the Windows identity credential");
  }
  result.resize(bytes);return result;
}
}
