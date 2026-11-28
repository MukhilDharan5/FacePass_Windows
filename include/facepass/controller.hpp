#pragma once
#include "ipc.hpp"
#include "storage.hpp"
#include "vision.hpp"
#include <map>
#include <set>
#include <mutex>
namespace facepass {
class Controller {
  Store store_;
  std::mutex mutex_;
  std::wstring activeSid_;
  std::map<std::wstring, Outcome> outcomes_;
  std::map<std::wstring, RetryPolicy> retries_;
  std::set<std::wstring> unlocked_;
  std::map<DWORD,std::wstring> lockedSessions_;
  std::map<DWORD,std::wstring> nativeSessions_;
  std::set<DWORD> automaticAttempts_;
  std::map<DWORD,std::uint64_t> lockEpochs_;
  std::uint64_t nextLockEpoch_ = 0;
  UnlockGrants grants_;
  std::vector<std::uint8_t> preview_;
  std::jthread worker_;
  bool busy_ = false;
  bool demo_;
  bool suspended_ = false;
  std::filesystem::path models_;
  Response snapshot(const std::wstring&);
  void start(const std::wstring&, bool enroll, const Config&, DWORD unlockSession=0xffffffff);
  bool backend();
  bool eligible(const std::wstring&, DWORD session);
  void automatic_scan(const std::wstring&, DWORD session);
public:
  Controller(bool demo, std::filesystem::path models);
  ~Controller();
  Response handle(const Caller&, const Request&);
  void session_event(DWORD event, DWORD session);
  void power_event(DWORD event);
};
}
