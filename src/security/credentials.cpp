#include "facepass/credentials.hpp"
#include <wincred.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <algorithm>
#include <cstring>

namespace facepass {
namespace {
template<size_t N> bool terminated(const wchar_t (&text)[N]) {
  return std::find(std::begin(text),std::end(text),L'\0')!=std::end(text);
}
std::wstring computer_name() {
  wchar_t name[MAX_COMPUTERNAME_LENGTH+1]{};DWORD size=std::size(name);
  if(!GetComputerNameW(name,&size)) fail("Read local computer name");
  return name;
}
bool microsoft_identity(const std::wstring& username) {
  return _wcsnicmp(username.c_str(),L"MicrosoftAccount\\",17)==0;
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
std::wstring windows_account_username(const std::wstring& username,const std::wstring& domain) {
  auto invalid=[](){throw std::runtime_error("Use .\\username, COMPUTER\\username, or MicrosoftAccount\\email for your own Windows account.");};
  if(username.empty() || username.size()>512 || domain.size()>512
      || username.find(L'\0')!=std::wstring::npos || domain.find(L'\0')!=std::wstring::npos) invalid();
  auto account=username,authority=domain;
  auto slash=account.find(L'\\');
  if(slash!=std::wstring::npos) {
    auto prefix=account.substr(0,slash);
    if(!authority.empty() && _wcsicmp(authority.c_str(),prefix.c_str())!=0) invalid();
    authority=prefix;account=account.substr(slash+1);
  }
  if(account.empty() || account.find(L'\\')!=std::wstring::npos) invalid();
  if(_wcsicmp(authority.c_str(),L"MicrosoftAccount")==0
      || (authority.empty() && account.find(L'@')!=std::wstring::npos))
    return microsoft_account_username(account,authority);
  auto machine=computer_name();
  if(!authority.empty() && authority!=L"." && _wcsicmp(authority.c_str(),machine.c_str())!=0) invalid();
  auto qualified=machine+L"\\"+account;
  if(qualified.size()>512) invalid();
  return qualified;
}
bool valid_windows_credential(const WindowsCredential& c) {
  if(c.version!=1 || !terminated(c.sid) || !terminated(c.username) || !terminated(c.password)
      || !c.password[0] || !c.sid[0]) return false;
  // Persist only canonical local-machine or Microsoft-account identities.
  try {if(_wcsicmp(windows_account_username(c.username).c_str(),c.username)!=0) return false;}
  catch(...) {return false;}
  PSID sid=nullptr; if(!ConvertStringSidToSidW(c.sid,&sid)) return false;
  bool ok=IsValidSid(sid) && !IsWellKnownSid(sid,WinLocalSystemSid)
      && !IsWellKnownSid(sid,WinLocalServiceSid) && !IsWellKnownSid(sid,WinNetworkServiceSid);
  LocalFree(sid); return ok;
}
Handle verify_windows_credential(const WindowsCredential& c) {
  if(!valid_windows_credential(c)) throw std::runtime_error("Use your local Windows account or Microsoft account and its password, not a PIN.");
  HANDLE raw=nullptr;
  std::wstring qualified=c.username;auto slash=qualified.find(L'\\');
  auto domain=qualified.substr(0,slash),username=qualified.substr(slash+1);
  if(!LogonUserW(username.c_str(),domain.c_str(),c.password,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&raw)) fail("Verify Windows account password");
  Handle token(raw);
  if(token_sid(token.get())!=c.sid) throw std::runtime_error("The password must belong to this Windows account.");
  return token;
}
VerifiedCredential prompt_windows_credential(HWND parent,bool saveForUnlock) {
  CREDUI_INFOW ui{}; ui.cbSize=sizeof(ui); ui.hwndParent=parent;
  ui.pszCaptionText=saveForUnlock?L"FacePass - save Windows password":L"FacePass enrollment";
  ui.pszMessageText=saveForUnlock
    ? L"Save your Windows password encrypted on this laptop for face unlock. For a local account enter .\\username and its password. MicrosoftAccount\\email also works. Do not enter your PIN."
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
    auto qualified=windows_account_username(user.data(),domain.data());
    result.credential.version=1;
    wcscpy_s(result.credential.sid,current_sid().c_str());
    wcscpy_s(result.credential.username,qualified.c_str());
    wcscpy_s(result.credential.password,password.data());
    result.token=verify_windows_credential(result.credential);
  } else {
    auto qualified=windows_account_username(user.data(),domain.data());
    auto slash=qualified.find(L'\\');
    auto authority=qualified.substr(0,slash),account=qualified.substr(slash+1);
    HANDLE raw=nullptr;
    if(!LogonUserW(account.c_str(),authority.c_str(),password.data(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&raw)) fail("Verify Windows account password");
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
std::vector<BYTE> pack_windows_credential(const WindowsCredential& c,bool unlockWorkstation) {
  if(!valid_windows_credential(c)) throw std::runtime_error("Invalid Windows credential.");
  if(!microsoft_identity(c.username)) {
    // Local accounts use a protected password and an offset-based interactive
    // logon, following Microsoft's Credential Provider sample.
    std::array<wchar_t,513> plain{};wcscpy_s(plain.data(),plain.size(),c.password);
    struct Wipe {void* p;size_t n;~Wipe(){SecureZeroMemory(p,n);}} wipe{plain.data(),sizeof(plain)};
    DWORD chars=0;CRED_PROTECTION_TYPE protection=CredUnprotected;
    if(CredProtectW(FALSE,plain.data(),static_cast<DWORD>(wcslen(plain.data())+1),nullptr,&chars,&protection)
        || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || !chars || chars>4096) fail("Size protected local password");
    std::vector<wchar_t> protectedPassword(chars);
    Wipe wipeProtected{protectedPassword.data(),protectedPassword.size()*sizeof(wchar_t)};
    if(!CredProtectW(FALSE,plain.data(),static_cast<DWORD>(wcslen(plain.data())+1),protectedPassword.data(),&chars,&protection)) fail("Protect local password");
    std::wstring qualified=c.username;auto slash=qualified.find(L'\\');
    auto domain=qualified.substr(0,slash),user=qualified.substr(slash+1);
    size_t passwordBytes=wcslen(protectedPassword.data())*sizeof(wchar_t);
    std::vector<BYTE> result(sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)+(domain.size()+user.size())*sizeof(wchar_t)+passwordBytes);
    auto logon=reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(result.data());
    logon->Logon.MessageType=unlockWorkstation?KerbWorkstationUnlockLogon:KerbInteractiveLogon;
    size_t offset=sizeof(*logon);
    auto append=[&](UNICODE_STRING& field,const wchar_t* text,size_t bytes) {
      field.Length=field.MaximumLength=static_cast<USHORT>(bytes);
      field.Buffer=reinterpret_cast<PWSTR>(offset);
      std::memcpy(result.data()+offset,text,bytes);offset+=bytes;
    };
    append(logon->Logon.LogonDomainName,domain.data(),domain.size()*sizeof(wchar_t));
    append(logon->Logon.UserName,user.data(),user.size()*sizeof(wchar_t));
    append(logon->Logon.Password,protectedPassword.data(),passwordBytes);
    return result;
  }
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
