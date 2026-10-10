#include "facepass/platform.hpp"
#include <wincred.h>
#include <array>
namespace facepass {
Handle recent_session_authentication() {
  HANDLE raw=nullptr;
  if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&raw)) fail("Open current Windows authentication token");
  Handle token(raw);
  if(!fresh_interactive_token(token.get())) throw std::runtime_error("Sign out and sign in with a native Windows method, then enroll within two minutes. This option does not collect a password.");
  return token;
}
Handle reauthenticate(HWND parent) {
  CREDUI_INFOW ui{}; ui.cbSize=sizeof(ui); ui.hwndParent=parent;
  ui.pszCaptionText=L"FacePass enrollment";
  ui.pszMessageText=L"Verify this Windows account before enrolling. Enter its password (a Windows Hello PIN cannot be used here). Credentials are discarded immediately.";
  ULONG package=0; void* credentials=nullptr; ULONG size=0; BOOL save=FALSE;
  auto error=CredUIPromptForWindowsCredentialsW(&ui,0,&package,nullptr,0,&credentials,&size,&save,CREDUIWIN_GENERIC);
  if(error!=ERROR_SUCCESS) fail("Windows enrollment verification",error);
  struct SecretBuffer { void* p; ULONG size; ~SecretBuffer(){ if(p){ SecureZeroMemory(p,size); CoTaskMemFree(p); } } } secret{credentials,size};
  std::array<wchar_t,513> user{},domain{},password{};
  struct Wipe { std::array<wchar_t,513>& value; ~Wipe(){SecureZeroMemory(value.data(),value.size()*sizeof(wchar_t));} } wipe{password};
  DWORD userLen=static_cast<DWORD>(user.size()), domainLen=static_cast<DWORD>(domain.size()), passLen=static_cast<DWORD>(password.size());
  if(!CredUnPackAuthenticationBufferW(0,credentials,size,user.data(),&userLen,domain.data(),&domainLen,password.data(),&passLen)) fail("Unpack enrollment verification");
  HANDLE raw=nullptr;
  if(!LogonUserW(user.data(),domain[0]?domain.data():nullptr,password.data(),LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&raw)) fail("Validate Windows account password");
  Handle token(raw);
  if(token_sid(token.get())!=current_sid()) throw std::runtime_error("Enrollment must verify the currently signed-in Windows account");
  if(!fresh_interactive_token(token.get())) throw std::runtime_error("Windows did not supply a fresh interactive authentication token");
  return token;
}
}
