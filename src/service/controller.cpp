#include "facepass/controller.hpp"
#include "facepass/capture.hpp"
#include <wtsapi32.h>
#include <sddl.h>
#include <algorithm>
#ifdef FACEPASS_AUTOMATIC_TESTING
#include "../../tests/automatic-runtime.hpp"
#endif
namespace facepass {
namespace {
DWORD active_console() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::console_session();
#else
  return WTSGetActiveConsoleSessionId();
#endif
}
bool password_backend() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::password_backend_enabled();
#else
  return password_unlock_enabled();
#endif
}
std::filesystem::path storage_root(bool demo) {
#ifdef FACEPASS_AUTOMATIC_TESTING
  (void)demo;return testing::store_root();
#else
  return data_dir(!demo);
#endif
}
bool service_store(bool demo) {
#ifdef FACEPASS_AUTOMATIC_TESTING
  (void)demo;return false;
#else
  return !demo;
#endif
}
CaptureResult capture(CaptureKind kind,const Config& config,const Template& enrolled,std::stop_token stop,const Progress& progress,const PreviewSink& preview) {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::capture(kind,config,enrolled,stop,progress,preview);
#else
  return supervised_capture(kind,config,enrolled,stop,progress,preview);
#endif
}
std::wstring session_sid(DWORD session);
bool locked_console(DWORD session) {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::session_locked(session);
#else
  wchar_t* raw=nullptr; DWORD bytes=0;
  if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSSessionInfoEx,&raw,&bytes)) return false;
  bool locked=bytes>=sizeof(WTSINFOEXW) && reinterpret_cast<WTSINFOEXW*>(raw)->Level==1
      && reinterpret_cast<WTSINFOEXW*>(raw)->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_LOCK;
  WTSFreeMemory(raw); return locked;
#endif
}
}
Controller::Controller(bool demo,std::filesystem::path models):store_(storage_root(demo),service_store(demo)),demo_(demo),models_(std::move(models)) {
  random_bytes({reinterpret_cast<std::uint8_t*>(&nextLockEpoch_),sizeof(nextLockEpoch_)});
}
Controller::~Controller() { worker_.request_stop(); if(worker_.joinable()) worker_.join(); }
bool Controller::backend() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return !demo_ && testing::backend_available();
#else
  ULONG id=0; return !demo_ && (password_backend() || (passwordless_enabled() && unlock_package_id(id)));
#endif
}
bool Controller::eligible(const std::wstring& sid,DWORD session) {
  return !demo_ && !suspended_ && session==active_console()
      && nativeSessions_.contains(session) && nativeSessions_.at(session)==sid
      && lockedSessions_.contains(session) && lockedSessions_.at(session)==sid && session_sid(session)==sid;
}
void Controller::automatic_scan(const std::wstring& sid,DWORD session) {
  // Called under mutex_ by either WTS lock/resume or an authenticated LogonUI
  // status poll. A poll arriving before the lock event can wait without failing.
  if(busy_ || automaticAttempts_.contains(session) || !eligible(sid,session)) return;
  auto config=store_.config(sid);
  if(config.mode!=Mode::Automatic || !store_.enrolled(sid)
      || (config.requireAfterRestart && !unlocked_.contains(sid))
      || !retries_[sid].allowed(std::chrono::steady_clock::now())) return;
  if(backend()) {
    if(password_backend() && !store_.credential_saved(sid)) return;
    config=unlock_config(config);
  }
  automaticAttempts_.insert(session);
  start(sid,false,config,backend()?session:0xffffffff);
  event_log(L"Automatic recognition started for the locked console; Windows controls credential submission.");
}
Response Controller::snapshot(const std::wstring& sid) {
  Response r; r.config=store_.config(sid); r.enrolled=store_.enrolled(sid);
  r.backendAvailable=backend();
  r.passwordBackedBackend=!demo_&&password_backend();
  r.credentialSaved=!demo_&&store_.credential_saved(sid);
  r.cameraActive=busy_&&sid==activeSid_;
  auto it=outcomes_.find(sid);
  if(it!=outcomes_.end()) { r.phase=it->second.phase; r.similarity=it->second.similarity; r.progress=it->second.progress; set_message(r,it->second.message); }
  else set_message(r,r.passwordBackedBackend?L"Face unlock uses the saved encrypted Windows account password.":r.backendAvailable?L"Ready. Passwordless unlock requires a locked native console session.":L"Ready. Face recognition can be tested; passwordless backend is not enabled/loaded.");
  if(r.config.mode==Mode::Off && !r.cameraActive) { r.phase=Phase::Disabled; set_message(r,L"Face scanning is off. Webcam is idle. Windows PIN/password remains available."); }
  auto retry=retries_.find(sid);
  if(retry!=retries_.end()&&!retry->second.allowed(std::chrono::steady_clock::now())) { r.phase=Phase::Cooldown; set_message(r,L"Retry limit reached. Wait "+std::to_wstring(retry->second.remaining(std::chrono::steady_clock::now()))+L" seconds. Use Windows PIN/password."); }
  return r;
}
void Controller::start(const std::wstring& sid,bool enrollment,const Config& config,DWORD unlockSession) {
  if(worker_.joinable()) worker_.join();
  grants_.revoke(sid);
  preview_.clear();
  busy_=true; activeSid_=sid; outcomes_[sid]={Phase::Capturing,0,0,L"Opening webcam..."};
  worker_=std::jthread([this,sid,enrollment,config,unlockSession](std::stop_token stop) {
    Outcome result;
    try {
      auto progress=[this,sid](const Outcome& value) { std::lock_guard lock(mutex_); outcomes_[sid]=value; };
      PreviewSink preview;
      if(unlockSession==0xffffffff)preview=[this](std::span<const std::uint8_t> frame){std::lock_guard lock(mutex_);preview_.assign(frame.begin(),frame.end());};
      if(enrollment) {
        auto captured=capture(CaptureKind::Enroll,config,{},stop,progress,preview);
        if(captured.outcome.phase!=Phase::Enrolled)throw std::runtime_error(narrow(captured.outcome.message));
        auto t=std::move(captured.enrolled);
        // Serialize cancellation/commit with configuration changes; off/cancel cannot commit late.
        std::lock_guard lock(mutex_);
        if(stop.stop_requested()) result={Phase::Cancelled,0,0,L"Enrollment cancelled."};
        else { store_.save(sid,t); result={Phase::Enrolled,0,100,L"Seven samples encrypted and saved for this Windows account."}; }
        for(auto& sample:t.samples) SecureZeroMemory(sample.data(),sizeof(sample));
      } else {
        auto t=store_.load(sid); result=capture(CaptureKind::Recognize,config,t,stop,progress,preview).outcome;
        for(auto& sample:t.samples) SecureZeroMemory(sample.data(),sizeof(sample));
      }
    } catch(const std::exception& ex) { result={stop.stop_requested()?Phase::Cancelled:Phase::Error,0,0,widen(ex.what())}; }
    {
      std::lock_guard lock(mutex_);
      if(stop.stop_requested()) result={Phase::Cancelled,0,0,L"Operation cancelled. Webcam released."};
      if(result.phase==Phase::Recognized && unlockSession!=0xffffffff && backend() && eligible(sid,unlockSession)) {
        try {grants_.issue(sid,unlockSession);result.message=L"Face verified. Press Space or Enter, or interact with the lock screen to continue.";}
        catch(const std::exception& ex){result={Phase::Error,0,0,widen(ex.what())};}
      }
      outcomes_[sid]=result;
      if(!enrollment && result.phase!=Phase::Cancelled) {
        if(result.phase==Phase::Recognized) retries_[sid].succeeded();
        else retries_[sid].failed(config,std::chrono::steady_clock::now());
      }
      busy_=false; activeSid_.clear();preview_.clear();
    }
    event_log(enrollment ? L"Enrollment operation completed; no Windows credential was submitted." : L"Recognition operation completed; no Windows credential was submitted.");
  });
}
Response Controller::handle(const Caller& caller,const Request& request) {
  std::lock_guard lock(mutex_);
  Response r;
  try {
    if(!authorize(caller,request.operation,request.targetSid)) { r.error=ERROR_ACCESS_DENIED; return r; }
    std::wstring sid=request.targetSid[0] ? request.targetSid : caller.sid;
    auto config=store_.config(sid);
    switch(request.operation) {
    case Operation::Status:
      if(caller.role==ClientRole::Provider) automatic_scan(sid,caller.session);
      break;
    case Operation::Configure:
      grants_.revoke(sid);
      store_.config(sid,request.config);
      if(busy_&&activeSid_==sid) worker_.request_stop();
      break;
    case Operation::Enroll:
    case Operation::Recognize:
      if(config.mode==Mode::Off) { r=snapshot(sid); r.error=ERROR_ACCESS_DISABLED_BY_POLICY; break; }
      if(busy_) { r=snapshot(sid); r.error=ERROR_BUSY; break; }
      if(caller.system && config.requireAfterRestart && !unlocked_.contains(sid)) {
        outcomes_[sid]={Phase::Rejected,0,0,L"Use Windows PIN/password once after the service starts, then retry."}; break;
      }
      if(request.operation==Operation::Recognize&&!store_.enrolled(sid)) { r.error=ERROR_NOT_FOUND; break; }
      if(!retries_[sid].allowed(std::chrono::steady_clock::now())) break;
      {
        DWORD unlockSession=0xffffffff;
        if(caller.role==ClientRole::Provider && backend()) {
          if(password_backend()&&!store_.credential_saved(sid)) {
            r.error=ERROR_NOT_FOUND;set_message(r,L"Save your Windows account password in FacePass Settings before using face unlock.");break;
          }
          if(!eligible(sid,caller.session)) {
            r.error=ERROR_ACCESS_DENIED; set_message(r,L"Passwordless unlock requires this account's locked console session and a native sign-in since service startup."); break;
          }
          unlockSession=caller.session;
          config=unlock_config(config);
          automaticAttempts_.insert(caller.session);
        }
        start(sid,request.operation==Operation::Enroll,config,unlockSession);
      } break;
    case Operation::Cancel:
      if(caller.role==ClientRole::Provider && (caller.session!=active_console() || session_sid(caller.session)!=sid)) {
        r.error=ERROR_ACCESS_DENIED;break;
      }
      if(caller.role==ClientRole::Provider && backend() && (!request.lockEpoch
          || !lockEpochs_.contains(caller.session) || lockEpochs_.at(caller.session)!=request.lockEpoch)) {
        // A delayed cancellation from an old LogonUI must not stop a new lock
        // or resume scan for the same account/session.
        r.error=ERROR_ACCESS_DENIED;break;
      }
      if(caller.role==ClientRole::Provider && lockedSessions_.contains(caller.session)
          && lockedSessions_.at(caller.session)==sid) automaticAttempts_.insert(caller.session);
      grants_.revoke(sid);
      if(busy_&&activeSid_==sid) worker_.request_stop(); break;
    case Operation::DeleteProfile:
      if(busy_&&activeSid_==sid) { r.error=ERROR_BUSY; break; }
      grants_.revoke(sid); store_.remove(sid); outcomes_.erase(sid); break;
    case Operation::ConsumeUnlock:
      if(!backend() || password_backend() || !eligible(sid,request.ticket.session) || !grants_.consume(request.ticket)) {
        r.error=ERROR_ACCESS_DENIED; set_message(r,L"Unlock authorization is missing, expired, consumed or belongs to another session.");
      }
      break;
    case Operation::SaveWindowsCredential:
      if(demo_ || !password_backend()) {r.error=ERROR_NOT_SUPPORTED;set_message(r,L"Password-backed unlock requires the installed FacePass Windows service.");break;}
      if(busy_) {r.error=ERROR_BUSY;break;}
      if(sid!=request.windowsCredential.sid) {r.error=ERROR_ACCESS_DENIED;break;}
      {auto verified=verify_windows_credential(request.windowsCredential);store_.credential(sid,request.windowsCredential);}
      grants_.revoke(sid);outcomes_[sid]={Phase::Idle,0,0,L"Windows account password verified and encrypted for face unlock."};
      break;
    case Operation::DeleteWindowsCredential:
      if(demo_) {r.error=ERROR_NOT_SUPPORTED;break;}
      if(caller.role==ClientRole::Provider && (caller.session!=active_console()
          || !lockedSessions_.contains(caller.session)||lockedSessions_.at(caller.session)!=sid)) {r.error=ERROR_ACCESS_DENIED;break;}
      store_.remove_credential(sid);grants_.revoke(sid);
      if(busy_&&activeSid_==sid)worker_.request_stop();
      outcomes_[sid]={Phase::Idle,0,0,L"Saved Windows password removed. Use Windows PIN/password until it is saved again."};
      break;
    case Operation::RetrieveWindowsCredential:
      if(demo_ || !password_backend() || caller.role!=ClientRole::Provider
          || caller.session!=request.ticket.session || !eligible(sid,caller.session) || !grants_.consume(request.ticket)) {
        r.error=ERROR_ACCESS_DENIED;set_message(r,L"No live, one-use face-unlock approval for this locked session.");break;
      }
      r=snapshot(sid);r.windowsCredential=store_.credential(sid);
      // Return directly; ordinary snapshot responses never contain credentials.
      return r;
    }
    if(!r.error) {
      r=snapshot(sid);
      if(caller.role==ClientRole::Provider) {
        r.unlockEligible=eligible(sid,caller.session);
        r.automaticAttempted=r.unlockEligible && automaticAttempts_.contains(caller.session);
        if(r.unlockEligible) r.lockEpoch=lockEpochs_.at(caller.session);
        if(r.backendAvailable && r.unlockEligible) r.ticket=grants_.peek(sid,caller.session);
      }
      if(caller.role==ClientRole::User && r.cameraActive) {
        r.previewSize=static_cast<unsigned>(preview_.size());std::copy(preview_.begin(),preview_.end(),r.preview.begin());
      }
    }
  } catch(const std::exception& ex) { r.error=ERROR_INVALID_DATA; set_message(r,widen(ex.what())); }
  return r;
}
namespace {
std::wstring session_sid(DWORD session) {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::session_owner(session);
#else
  wchar_t* user=nullptr; wchar_t* domain=nullptr; DWORD size=0;
  if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSUserName,&user,&size)) return {};
  std::wstring name=user; WTSFreeMemory(user);
  if(name.empty()) return {};
  if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSDomainName,&domain,&size)) { if(domain&&*domain) name=std::wstring(domain)+L"\\"+name; WTSFreeMemory(domain); }
  DWORD sidSize=SECURITY_MAX_SID_SIZE,domainSize=256; std::vector<BYTE> sid(sidSize); wchar_t resolved[256]{}; SID_NAME_USE use{};
  if(!LookupAccountNameW(nullptr,name.c_str(),sid.data(),&sidSize,resolved,&domainSize,&use)) return {};
  wchar_t* text=nullptr; if(!ConvertSidToStringSidW(sid.data(),&text)) return {};
  std::wstring value=text; LocalFree(text); return value;
#endif
}
}
void Controller::session_event(DWORD event,DWORD session) {
  if(demo_) return;
  // Disconnect/logoff can arrive after Windows has already switched consoles.
  // Revoke using the recorded owner before testing the current console ID.
  if(event==WTS_SESSION_LOGOFF || event==WTS_CONSOLE_DISCONNECT || event==WTS_REMOTE_DISCONNECT) {
    std::lock_guard lock(mutex_);
    for(auto* sessions:{&nativeSessions_,&lockedSessions_}) {
      auto it=sessions->find(session);
      if(it!=sessions->end()) {
        if(busy_ && activeSid_==it->second) worker_.request_stop();
        grants_.revoke(it->second);
        if(event==WTS_SESSION_LOGOFF) unlocked_.erase(it->second);
        sessions->erase(it);
      }
    }
    automaticAttempts_.erase(session);lockEpochs_.erase(session); return;
  }
  if(session!=active_console()) return;
  auto sid=session_sid(session);
  if(sid.empty()) {
    std::lock_guard lock(mutex_);
    if(nativeSessions_.contains(session)) sid=nativeSessions_.at(session);
    else if(lockedSessions_.contains(session)) sid=lockedSessions_.at(session);
  }
  if(sid.empty()) return;
  if(event==WTS_SESSION_DESKTOP_READY) {
    std::lock_guard lock(mutex_); lockedSessions_.erase(session); automaticAttempts_.erase(session); lockEpochs_.erase(session); grants_.revoke(sid);
    if(busy_) worker_.request_stop();
  } else if(event==WTS_SESSION_UNLOCK||event==WTS_SESSION_LOGON) {
    std::lock_guard lock(mutex_); unlocked_.insert(sid);
    nativeSessions_[session]=sid; lockedSessions_.erase(session); automaticAttempts_.erase(session); lockEpochs_.erase(session); grants_.revoke(sid);
    if(busy_) worker_.request_stop();
  } else if(event==WTS_SESSION_LOCK || (event==WTS_CONSOLE_CONNECT && locked_console(session))) {
    try {
      std::lock_guard lock(mutex_);
      if(suspended_) return;
      if(!lockedSessions_.contains(session) || lockedSessions_.at(session)!=sid) {
        lockedSessions_[session]=sid; automaticAttempts_.erase(session); grants_.revoke(sid);
        if(++nextLockEpoch_==0) ++nextLockEpoch_;
        lockEpochs_[session]=nextLockEpoch_;
      }
      if(busy_ && activeSid_!=sid) worker_.request_stop();
      automatic_scan(sid,session);
    } catch(const std::exception& ex) { event_log(L"Automatic scan unavailable: "+widen(ex.what()),EVENTLOG_WARNING_TYPE); }
  }
}
void Controller::power_event(DWORD event) {
  if(demo_) return;
  if(event==PBT_APMSUSPEND) {
    std::lock_guard lock(mutex_); suspended_=true;
    worker_.request_stop(); grants_.clear(); lockedSessions_.clear(); automaticAttempts_.clear(); lockEpochs_.clear();
  } else if(event==PBT_APMRESUMEAUTOMATIC || event==PBT_APMRESUMESUSPEND) {
    {std::lock_guard lock(mutex_); suspended_=false;}
    // Resume never manufactures native sign-in provenance. Only an already
    // recorded session whose OS lock flag is set can start a fresh attempt.
    session_event(WTS_CONSOLE_CONNECT,active_console());
  }
}
}
