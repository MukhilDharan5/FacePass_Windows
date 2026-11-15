#include "facepass/platform.hpp"
#include "facepass/credentials.hpp"
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
  return prompt_windows_credential(parent,false).token;
}
}
