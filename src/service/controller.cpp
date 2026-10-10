#include "facepass/controller.hpp"
#include "facepass/capture.hpp"
#include <wtsapi32.h>
#include <sddl.h>
#include <algorithm>
namespace facepass {
namespace { std::wstring session_sid(DWORD session); }
Controller::Controller(bool demo,std::filesystem::path models):store_(data_dir(!demo),!demo),demo_(demo),models_(std::move(models)) {}
Controller::~Controller() { worker_.request_stop(); if(worker_.joinable()) worker_.join(); }
bool Controller::backend() { ULONG id=0; return !demo_ && (password_unlock_enabled() || (passwordless_enabled() && unlock_package_id(id))); }
Response Controller::snapshot(const std::wstring& sid) {
  Response r; r.config=store_.config(sid); r.enrolled=store_.enrolled(sid);
  r.backendAvailable=backend();
  r.passwordBackedBackend=!demo_&&password_unlock_enabled();
  r.credentialSaved=!demo_&&store_.credential_saved(sid);
  r.cameraActive=busy_&&sid==activeSid_;
  auto it=outcomes_.find(sid);
  if(it!=outcomes_.end()) { r.phase=it->second.phase; r.similarity=it->second.similarity; r.progress=it->second.progress; set_message(r,it->second.message); }
  else set_message(r,r.passwordBackedBackend?L"Face unlock uses the saved encrypted Microsoft-account password.":r.backendAvailable?L"Ready. Passwordless unlock requires a locked native console session.":L"Ready. Face recognition can be tested; passwordless backend is not enabled/loaded.");
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
        auto captured=supervised_capture(CaptureKind::Enroll,config,{},stop,progress,preview);
        if(captured.outcome.phase!=Phase::Enrolled)throw std::runtime_error(narrow(captured.outcome.message));
        auto t=std::move(captured.enrolled);
        // Serialize cancellation/commit with configuration changes; off/cancel cannot commit late.
        std::lock_guard lock(mutex_);
        if(stop.stop_requested()) result={Phase::Cancelled,0,0,L"Enrollment cancelled."};
        else { store_.save(sid,t); result={Phase::Enrolled,0,100,L"Seven samples encrypted and saved for this Windows account."}; }
        for(auto& sample:t.samples) SecureZeroMemory(sample.data(),sizeof(sample));
      } else {
        auto t=store_.load(sid); result=supervised_capture(CaptureKind::Recognize,config,t,stop,progress,preview).outcome;
        for(auto& sample:t.samples) SecureZeroMemory(sample.data(),sizeof(sample));
      }
    } catch(const std::exception& ex) { result={stop.stop_requested()?Phase::Cancelled:Phase::Error,0,0,widen(ex.what())}; }
    {
      std::lock_guard lock(mutex_);
      if(stop.stop_requested()) result={Phase::Cancelled,0,0,L"Operation cancelled. Webcam released."};
      if(result.phase==Phase::Recognized && unlockSession!=0xffffffff && backend()
          && nativeSessions_.contains(unlockSession) && nativeSessions_.at(unlockSession)==sid
          && lockedSessions_.contains(unlockSession) && lockedSessions_.at(unlockSession)==sid
          && unlockSession==WTSGetActiveConsoleSessionId() && session_sid(unlockSession)==sid) {
        try {grants_.issue(sid,unlockSession);result.message=config.profile==Profile::Instant?L"2D face matched. Instant unlock approval is ready.":L"Face and active challenge matched. One-use face unlock approval is ready.";}
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
    case Operation::Status: break;
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
          if(password_unlock_enabled()&&!store_.credential_saved(sid)) {
            r.error=ERROR_NOT_FOUND;set_message(r,L"Save your Microsoft-account password in FacePass Settings before using face unlock.");break;
          }
          if(caller.session!=WTSGetActiveConsoleSessionId() || !nativeSessions_.contains(caller.session)
              || nativeSessions_.at(caller.session)!=sid || !lockedSessions_.contains(caller.session)
              || lockedSessions_.at(caller.session)!=sid || session_sid(caller.session)!=sid) {
            r.error=ERROR_ACCESS_DENIED; set_message(r,L"Passwordless unlock requires this account's locked console session and a native sign-in since service startup."); break;
          }
          unlockSession=caller.session;
          config=unlock_config(config);
        }
        start(sid,request.operation==Operation::Enroll,config,unlockSession);
      } break;
    case Operation::Cancel:
      grants_.revoke(sid);
      if(busy_&&activeSid_==sid) worker_.request_stop(); break;
    case Operation::DeleteProfile:
      if(busy_&&activeSid_==sid) { r.error=ERROR_BUSY; break; }
      grants_.revoke(sid); store_.remove(sid); outcomes_.erase(sid); break;
    case Operation::ConsumeUnlock:
      if(!backend() || password_unlock_enabled() || !lockedSessions_.contains(request.ticket.session)
          || lockedSessions_.at(request.ticket.session)!=sid || !nativeSessions_.contains(request.ticket.session)
          || nativeSessions_.at(request.ticket.session)!=sid || request.ticket.session!=WTSGetActiveConsoleSessionId()
          || session_sid(request.ticket.session)!=sid || !grants_.consume(request.ticket)) {
        r.error=ERROR_ACCESS_DENIED; set_message(r,L"Unlock authorization is missing, expired, consumed or belongs to another session.");
      }
      break;
    case Operation::SaveWindowsCredential:
      if(demo_ || !password_unlock_enabled()) {r.error=ERROR_NOT_SUPPORTED;set_message(r,L"Password-backed unlock requires the installed FacePass Windows service.");break;}
      if(busy_) {r.error=ERROR_BUSY;break;}
      if(sid!=request.windowsCredential.sid) {r.error=ERROR_ACCESS_DENIED;break;}
      {auto verified=verify_windows_credential(request.windowsCredential);store_.credential(sid,request.windowsCredential);}
      grants_.revoke(sid);outcomes_[sid]={Phase::Idle,0,0,L"Microsoft-account password verified and encrypted for face unlock."};
      break;
    case Operation::DeleteWindowsCredential:
      if(demo_) {r.error=ERROR_NOT_SUPPORTED;break;}
      if(caller.role==ClientRole::Provider && (caller.session!=WTSGetActiveConsoleSessionId()
          || !lockedSessions_.contains(caller.session)||lockedSessions_.at(caller.session)!=sid)) {r.error=ERROR_ACCESS_DENIED;break;}
      store_.remove_credential(sid);grants_.revoke(sid);
      if(busy_&&activeSid_==sid)worker_.request_stop();
      outcomes_[sid]={Phase::Idle,0,0,L"Saved Windows password removed. Use Windows PIN/password until it is saved again."};
      break;
    case Operation::RetrieveWindowsCredential:
      if(demo_ || !password_unlock_enabled() || caller.role!=ClientRole::Provider
          || caller.session!=request.ticket.session || request.ticket.session!=WTSGetActiveConsoleSessionId()
          || !lockedSessions_.contains(caller.session)||lockedSessions_.at(caller.session)!=sid
          || !nativeSessions_.contains(caller.session)||nativeSessions_.at(caller.session)!=sid
          || session_sid(caller.session)!=sid || !grants_.consume(request.ticket)) {
        r.error=ERROR_ACCESS_DENIED;set_message(r,L"No live, one-use face-unlock approval for this locked session.");break;
      }
      r=snapshot(sid);r.windowsCredential=store_.credential(sid);
      // Return directly; ordinary snapshot responses never contain credentials.
      return r;
    }
    if(!r.error) {
      r=snapshot(sid);
      if(caller.role==ClientRole::Provider && r.backendAvailable) r.ticket=grants_.peek(sid,caller.session);
      if(caller.role==ClientRole::User && r.cameraActive) {
        r.previewSize=static_cast<unsigned>(preview_.size());std::copy(preview_.begin(),preview_.end(),r.preview.begin());
      }
    }
  } catch(const std::exception& ex) { r.error=ERROR_INVALID_DATA; set_message(r,widen(ex.what())); }
  return r;
}
namespace {
std::wstring session_sid(DWORD session) {
  wchar_t* user=nullptr; wchar_t* domain=nullptr; DWORD size=0;
  if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSUserName,&user,&size)) return {};
  std::wstring name=user; WTSFreeMemory(user);
  if(name.empty()) return {};
  if(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSDomainName,&domain,&size)) { if(domain&&*domain) name=std::wstring(domain)+L"\\"+name; WTSFreeMemory(domain); }
  DWORD sidSize=SECURITY_MAX_SID_SIZE,domainSize=256; std::vector<BYTE> sid(sidSize); wchar_t resolved[256]{}; SID_NAME_USE use{};
  if(!LookupAccountNameW(nullptr,name.c_str(),sid.data(),&sidSize,resolved,&domainSize,&use)) return {};
  wchar_t* text=nullptr; if(!ConvertSidToStringSidW(sid.data(),&text)) return {};
  std::wstring value=text; LocalFree(text); return value;
}
}
void Controller::session_event(DWORD event,DWORD session) {
  if(demo_||session!=WTSGetActiveConsoleSessionId()) return;
  auto sid=session_sid(session);
  if(sid.empty()) {
    std::lock_guard lock(mutex_);
    if(nativeSessions_.contains(session)) sid=nativeSessions_.at(session);
    else if(lockedSessions_.contains(session)) sid=lockedSessions_.at(session);
  }
  if(sid.empty()) return;
  if(event==WTS_SESSION_UNLOCK||event==WTS_SESSION_LOGON) {
    std::lock_guard lock(mutex_); unlocked_.insert(sid);
    nativeSessions_[session]=sid; lockedSessions_.erase(session); grants_.revoke(sid);
    if(busy_&&activeSid_==sid) worker_.request_stop();
  } else if(event==WTS_SESSION_LOCK) {
    try {
      { std::lock_guard lock(mutex_); lockedSessions_[session]=sid; grants_.revoke(sid); }
      auto c=store_.config(sid);
      // Passwordless jobs begin when the OS loads/selects its tile. A diagnostic
      // lock scan is never promoted to an unlock authorization.
      if(c.mode==Mode::Automatic && !backend()) { Request r; r.operation=Operation::Recognize; wcsncpy_s(r.targetSid,sid.c_str(),_TRUNCATE); handle({L"S-1-5-18",true,false,ClientRole::Provider,session},r); }
    } catch(const std::exception& ex) { event_log(L"Automatic scan unavailable: "+widen(ex.what()),EVENTLOG_WARNING_TYPE); }
  } else if(event==WTS_SESSION_LOGOFF||event==WTS_CONSOLE_DISCONNECT) {
    std::lock_guard lock(mutex_); if(busy_&&activeSid_==sid) worker_.request_stop(); unlocked_.erase(sid);
    nativeSessions_.erase(session); lockedSessions_.erase(session); grants_.revoke(sid);
  }
}
}
