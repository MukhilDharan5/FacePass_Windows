#pragma once
// Compiled only into FacePassAutomaticTests. Production binaries have no test
// exports, alternate IPC endpoint, identity override, or synthetic capture path.
#include "facepass/capture.hpp"
#include "facepass/ipc.hpp"
#include <optional>
namespace facepass::testing {
std::filesystem::path store_root();
DWORD console_session();
std::wstring session_owner(DWORD);
bool session_locked(DWORD);
bool backend_available();
bool password_backend_enabled();
CaptureResult capture(CaptureKind,const Config&,const Template&,std::stop_token,const Progress&,const PreviewSink&);
bool trusted_provider();
Response provider_request(const Request&,std::stop_token);
std::uint64_t provider_now();
std::optional<DWORD> last_input_tick();
DWORD input_now();
bool on_logon_input_desktop();
}
