#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <stop_token>

namespace facepass {
inline constexpr wchar_t ServiceName[] = L"FacePassService";
inline constexpr wchar_t ProviderId[] = L"{A528A337-5D76-4B10-89F8-7B476F2BA491}";
inline constexpr std::uint32_t ProtocolMagic = 0x46505331;
inline constexpr std::uint32_t ProtocolVersion = 3;
inline constexpr std::size_t EmbeddingSize = 128;
inline constexpr std::size_t SampleCount = 7;
inline constexpr std::size_t PreviewCapacity = 32768;
enum class Mode : std::uint32_t { Off, Manual, Automatic };
enum class Profile : std::uint32_t { Convenience, Balanced, Strict, Instant };
enum class Operation : std::uint32_t { Status, Configure, Enroll, Recognize, Cancel, DeleteProfile, ConsumeUnlock, SaveWindowsCredential, DeleteWindowsCredential, RetrieveWindowsCredential };
enum class Phase : std::uint32_t { Idle, Disabled, Capturing, Challenge, Enrolled, Recognized, Rejected, Error, Cooldown, Cancelled };
struct Config {
  std::uint32_t version = 1;
  Mode mode = Mode::Off;
  Profile profile = Profile::Balanced;
  std::uint32_t camera = 0;
  std::uint32_t attempts = 3;
  std::uint32_t cooldownSeconds = 30;
  std::uint32_t timeoutSeconds = 20;
  float threshold = 0.45f;
  std::uint32_t requireAfterRestart = 1;
};
using Embedding = std::array<float, EmbeddingSize>;
struct Template {
  std::vector<Embedding> samples;
};
struct Outcome {
  Phase phase = Phase::Idle;
  float similarity = 0;
  std::uint32_t progress = 0;
  std::wstring message = L"Ready.";
};
using Progress = std::function<void(const Outcome&)>;
bool valid_config(const Config& config);
Config unlock_config(Config config);
float cosine(const Embedding& a, const Embedding& b);
float match(const Embedding& probe, const Template& enrolled);
class RetryPolicy {
  unsigned failures_ = 0;
  std::chrono::steady_clock::time_point until_{};
public:
  bool allowed(std::chrono::steady_clock::time_point now) const;
  void failed(const Config&, std::chrono::steady_clock::time_point);
  void succeeded();
  unsigned remaining(std::chrono::steady_clock::time_point) const;
};
// Ordinary user-session tests deliberately cannot authorize Windows unlock.
// The service separately authorizes trusted LogonUI jobs for its custom package.
struct DiagnosticRecognition {
  static constexpr bool available() { return false; }
  static constexpr const wchar_t* reason() { return L"Face matched. This diagnostic scan does not authorize Windows unlock."; }
};
}
