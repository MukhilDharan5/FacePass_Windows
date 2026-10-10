#pragma once
#include "types.hpp"
#include "platform.hpp"
#include "unlock.hpp"
#include "credentials.hpp"
#include <thread>
#include <atomic>

namespace facepass {
#pragma pack(push, 1)
struct Hello {
  std::uint32_t magic = ProtocolMagic;
  std::uint32_t version = ProtocolVersion;
  std::array<std::uint8_t,32> nonce{};
  std::uint64_t expires = 0;
};
struct Request {
  std::uint32_t magic = ProtocolMagic;
  std::uint32_t version = ProtocolVersion;
  std::array<std::uint8_t,32> nonce{};
  Operation operation = Operation::Status;
  wchar_t targetSid[192]{}; // Only SYSTEM may name another user, and only for status/scanning.
  Config config{};
  UnlockTicket ticket{}; // Only LSASS may consume a recognition authorization.
  WindowsCredential windowsCredential{}; // Own-account verified setup only.
};
struct Response {
  std::uint32_t magic = ProtocolMagic;
  std::uint32_t version = ProtocolVersion;
  std::array<std::uint8_t,32> nonce{};
  DWORD error = ERROR_SUCCESS;
  Config config{};
  Phase phase = Phase::Idle;
  std::uint32_t enrolled = 0;
  std::uint32_t cameraActive = 0;
  std::uint32_t progress = 0;
  std::uint32_t backendAvailable = 0;
  std::uint32_t passwordBackedBackend = 0;
  std::uint32_t credentialSaved = 0;
  float similarity = 0;
  wchar_t message[512]{};
  UnlockTicket ticket{}; // Sent only to the OS LogonUI process, never ordinary clients.
  WindowsCredential windowsCredential{}; // Only trusted LogonUI after one-use approval.
  std::uint32_t previewSize = 0;
  std::array<std::uint8_t,PreviewCapacity> preview{}; // Account-scoped transient JPEG, never persisted.
};
#pragma pack(pop)
enum class ClientRole { User, Provider, Authority };
struct Caller {
  std::wstring sid; bool system = false; bool fresh = false;
  ClientRole role = ClientRole::User;
  DWORD session = 0xffffffff;
};
bool valid_request(const Hello&, const Request&, std::uint64_t now);
bool authorize(const Caller&, Operation, const std::wstring& target);
using RequestHandler = std::function<Response(const Caller&,const Request&)>;
Response call(const Request&, bool demo = false, HANDLE enrollmentToken = nullptr);
class PipeServer {
  bool demo_;
  RequestHandler handler_;
  Handle pipe_;
public:
  PipeServer(bool demo, RequestHandler handler);
  void run(std::stop_token);
};
void set_message(Response&, const std::wstring&);
}
