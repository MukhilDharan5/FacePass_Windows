#include "facepass/ipc.hpp"
#include <credentialprovider.h>
#include <shlwapi.h>
#include <shlguid.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <new>
#include <cstring>
#include <optional>
#ifdef FACEPASS_AUTOMATIC_TESTING
#include "../../tests/automatic-runtime.hpp"
#endif
using namespace facepass;
namespace {
const CLSID ProviderClsid={0xa528a337,0x5d76,0x4b10,{0x89,0xf8,0x7b,0x47,0x6f,0x2b,0xa4,0x91}};
HINSTANCE module=nullptr;
std::atomic<long> objects=0;
constexpr DWORD FieldCount=5;
bool trusted_provider() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::trusted_provider();
#else
  return is_system_sid(current_sid());
#endif
}
bool password_backend_enabled() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::password_backend_enabled();
#else
  return password_unlock_enabled();
#endif
}
std::uint64_t provider_now() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::provider_now();
#else
  return unix_millis();
#endif
}
std::optional<DWORD> last_input_tick() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::last_input_tick();
#else
  LASTINPUTINFO input{sizeof(input)};
  if(!GetLastInputInfo(&input))return {};
  return input.dwTime;
#endif
}
DWORD input_now() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::input_now();
#else
  return GetTickCount();
#endif
}
bool on_logon_input_desktop() {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::on_logon_input_desktop();
#else
  auto desktop=GetThreadDesktop(GetCurrentThreadId());
  wchar_t name[256]{};BOOL input=FALSE;
  return desktop && GetUserObjectInformationW(desktop,UOI_NAME,name,sizeof(name),nullptr)
    && _wcsicmp(name,L"Winlogon")==0
    && GetUserObjectInformationW(desktop,UOI_IO,&input,sizeof(input),nullptr) && input;
#endif
}
Response provider_call(const Request& request,std::stop_token stop={}) {
#ifdef FACEPASS_AUTOMATIC_TESTING
  return testing::provider_request(request,stop);
#else
  return call(request,false,nullptr,stop);
#endif
}
void trace(const std::wstring& message) { event_log(L"Credential Provider: "+message); }
std::wstring status_code(NTSTATUS status) { wchar_t text[16]{};swprintf_s(text,L"0x%08lX",static_cast<ULONG>(status));return text; }
struct Notifications {
  ICredentialProviderEvents* events=nullptr;
  UINT_PTR context=0;
  ~Notifications(){if(events)events->Release();}
};
class Credential final : public ICredentialProviderCredential2 {
  friend class Provider;
  std::atomic<ULONG> refs_{1};
  std::wstring sid_;
  bool unlockWorkstation_=false;
  std::wstring text_=L"Use Windows PIN/password, or select FacePass to scan.";
  ICredentialProviderCredentialEvents* events_=nullptr;
  ICredentialProviderCredentialEvents2* events2_=nullptr;
  HWND window_=nullptr;
  std::jthread worker_;
  std::mutex mutex_;
  std::wstring pending_;
  UnlockTicket ticket_{},pendingTicket_{};
  std::array<std::uint8_t,32> serializedNonce_{};
  std::array<std::uint8_t,32> notifiedNonce_{};
  std::array<std::uint8_t,32> interactionNonce_{};
  DWORD inputBaseline_=0,inputArmedAt_=0;
  bool inputArmed_=false,inputConfirmed_=false;
  std::atomic<bool> workerActive_{false};
  std::uint64_t generation_=0,pendingGeneration_=0;
  bool automatic_=false,pendingAutomatic_=false;
  bool pendingManualStart_=false;
  std::weak_ptr<Notifications> notifications_;
  bool selected_=false;
  bool has_approval() const { return (selected_ || automatic_) && ticket_.nonce!=serializedNonce_ && valid_ticket(ticket_,provider_now()) && sid_==ticket_.sid; }
  void refresh_interaction() {
    if(!has_approval()) {interactionNonce_={};inputArmed_=inputConfirmed_=false;return;}
    if(interactionNonce_!=ticket_.nonce) {interactionNonce_=ticket_.nonce;inputArmed_=inputConfirmed_=false;trace(L"face verified; awaiting lock-screen interaction");}
    const auto input=last_input_tick();
    if(!input) {inputArmed_=inputConfirmed_=false;return;}
    const auto now=input_now();
    if(!inputArmed_ || !on_logon_input_desktop()) {
      inputBaseline_=*input;inputArmedAt_=now;inputArmed_=true;inputConfirmed_=false;return;
    }
    // DWORD subtraction handles uptime wrap. Reject stale/future timestamps:
    // GetLastInputInfo is session-specific and its tick is not always monotonic.
    const DWORD sinceArm=*input-inputArmedAt_,elapsed=now-inputArmedAt_;
    if(!inputConfirmed_ && *input!=inputBaseline_ && sinceArm>0 && sinceArm<=elapsed) {
      inputConfirmed_=true;trace(L"lock-screen interaction confirmed after face verification");
    }
  }
  static LRESULT CALLBACK wndproc(HWND window,UINT message,WPARAM w,LPARAM l) {
    auto self=reinterpret_cast<Credential*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE) { self=static_cast<Credential*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams); SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self)); }
    if(message==WM_APP+1&&self) {
      bool startManual=false;
      { std::lock_guard lock(self->mutex_);
        if(self->pendingGeneration_!=self->generation_) return 0;
        self->text_=self->pending_; self->ticket_=self->pendingTicket_; self->automatic_=self->pendingAutomatic_;
        startManual=self->pendingManualStart_ && self->selected_;
      }
      if(startManual) {try{self->scan(false);}catch(...){self->post(L"Cannot start face scan. Use Windows PIN/password.",self->generation_);}return 0;}
      self->refresh_interaction();
      if(self->has_approval())self->text_=self->ready()?L"Face verified. Continuing to Windows...":L"Face verified. Press Space or Enter, or interact with the lock screen to continue.";
      if(self->events_&&self->selected_) {
        if(self->events2_) self->events2_->BeginFieldUpdates();
        self->events_->SetFieldString(self,2,self->text_.c_str());
        if(self->events2_) self->events2_->EndFieldUpdates();
      }
      if(self->ready() && self->ticket_.nonce!=self->notifiedNonce_)
        if(auto notify=self->notifications_.lock();notify && notify->events) {
          self->notifiedNonce_=self->ticket_.nonce;
          trace(L"face approval received; selected="+std::to_wstring(self->selected_)+L"; automatic="+std::to_wstring(self->automatic_));
          // Both a live approval and later lock-screen input are required
          // before Windows is asked to submit this credential.
          auto hr=notify->events->CredentialsChanged(notify->context);
          trace(L"interaction-confirmed sign-in requested; result="+status_code(hr));
        }
      return 0;
    }
    return DefWindowProcW(window,message,w,l);
  }
  void post(const std::wstring& text,std::uint64_t generation) { {std::lock_guard lock(mutex_);pendingGeneration_=generation;pending_=text;pendingTicket_={};pendingAutomatic_=false;pendingManualStart_=false;} if(window_) PostMessageW(window_,WM_APP+1,0,0); }
  void post(const Response& response,std::uint64_t generation,bool startManual=false) {
    {std::lock_guard lock(mutex_);pendingGeneration_=generation;pending_=response.message;
      if(response.phase==Phase::Recognized && response.unlockEligible && !valid_ticket(response.ticket,provider_now()))pending_=L"Face confirmation expired. Select Scan again or use Windows PIN/password.";
      pendingTicket_=response.ticket;pendingAutomatic_=response.config.mode==Mode::Automatic;pendingManualStart_=startManual;}
    if(window_)PostMessageW(window_,WM_APP+1,0,0);
  }
  void scan(bool explicitRequest,bool automaticOnly=false) {
    // Selection and repeated Advise must not interrupt a background scan or
    // revoke an approval during Windows' credential re-enumeration.
    if(workerActive_ && !explicitRequest) return;
    if(worker_.joinable()) { worker_.request_stop(); worker_.join(); }
    auto sid=sid_;
    ticket_={}; automatic_=false; workerActive_=true;
    const auto generation=++generation_;
    try { worker_=std::jthread([this,sid,explicitRequest,automaticOnly,generation](std::stop_token stop) {
      struct Done {std::atomic<bool>& active;~Done(){active=false;}} done{workerActive_};
      Request r; wcsncpy_s(r.targetSid,sid.c_str(),_TRUNCATE);
      bool trusted=false,cancel=false;
      std::uint64_t lockEpoch=0;
      try {
        // Loading this DLL in a settings/test process must never start a sign-in scan.
        if(!trusted_provider()) return;
        trusted=true;
        auto response=provider_call(r,stop);
        lockEpoch=response.lockEpoch;
        if(automaticOnly && (response.config.mode!=Mode::Automatic || !response.backendAvailable)) {
          // Selection may arrive while the initial mode query is in flight.
          // Finish the probe and let the UI honor that pending manual selection.
          workerActive_=false;post(response,generation,response.config.mode!=Mode::Off);return;
        }
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(response.config.timeoutSeconds+5+UnlockLifetimeSeconds);
        bool requested=false;
        while(!stop.stop_requested()) {
          if(response.lockEpoch) lockEpoch=response.lockEpoch;
          if(response.config.mode==Mode::Off || (automaticOnly && response.config.mode!=Mode::Automatic)) {post(response,generation);break;}
          const bool approved=valid_ticket(response.ticket,provider_now());
          const bool manualRequest=!automaticOnly && (explicitRequest || response.config.mode==Mode::Manual || !response.backendAvailable);
          if(manualRequest && !requested && !approved && !response.cameraActive) {
            r.operation=Operation::Recognize; response=provider_call(r,stop); requested=true;
          }
          if(stop.stop_requested()) break;
          post(response,generation);
          const bool watchAutomatic=response.config.mode==Mode::Automatic && response.backendAvailable;
          if(!response.cameraActive && !valid_ticket(response.ticket,provider_now())
              && !watchAutomatic && (requested || (response.unlockEligible && response.automaticAttempted))) break;
          if(!watchAutomatic && std::chrono::steady_clock::now()>=deadline) {cancel=true;post(L"Face scan timed out. Use Windows PIN/password or Scan again.",generation);break;}
          // Automatic mode only observes status. The service starts one scan per
          // lock/resume; an early poll waits for WTS without restarting capture.
          // Stay subscribed after failure/expiry: sleep/resume can reuse the
          // same advised provider without another Advise or SetSelected call.
          const int intervals=response.cameraActive || valid_ticket(response.ticket,provider_now())?1:4;
          for(int i=0;i<intervals&&!stop.stop_requested();++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
          if(stop.stop_requested()) break;
          r.operation=Operation::Status; response=provider_call(r,stop);
        }
      } catch(const std::exception& ex) {
        cancel=true;
        if(!stop.stop_requested()) post(L"FacePass unavailable: "+widen(ex.what())+L". Use Windows PIN/password.",generation);
      }
      if(trusted && (stop.stop_requested() || cancel)) {r.operation=Operation::Cancel;r.lockEpoch=lockEpoch;try{provider_call(r);}catch(...){}}
    }); } catch(...) {workerActive_=false;throw;}
  }
public:
  explicit Credential(std::wstring sid,std::weak_ptr<Notifications> notifications,bool unlockWorkstation):sid_(std::move(sid)),unlockWorkstation_(unlockWorkstation),notifications_(std::move(notifications)) {
    ++objects;
    WNDCLASSW wc{}; wc.lpfnWndProc=wndproc; wc.hInstance=module; wc.lpszClassName=L"FacePassProviderStatus";
    RegisterClassW(&wc);
    window_=CreateWindowExW(0,wc.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,module,this);
  }
  bool ready() const { return has_approval() && inputConfirmed_ && on_logon_input_desktop(); }
  const std::wstring& sid() const {return sid_;}
  void start_automatic(){if(has_approval())return;try{scan(false,true);}catch(...){post(L"Automatic face unlock unavailable. Use Windows PIN/password.",generation_);}}
  void stop_scan(bool wait=false) {
    ++generation_; ticket_={}; automatic_=false; interactionNonce_={};inputArmed_=inputConfirmed_=false;worker_.request_stop();
    if(wait && worker_.joinable()) worker_.join();
  }
  ~Credential() {
    stop_scan(true);
    if(events2_) events2_->Release(); if(events_) events_->Release();
    if(window_) DestroyWindow(window_); UnregisterClassW(L"FacePassProviderStatus",module); --objects;
  }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p) override {
    if(!p) return E_POINTER; *p=nullptr;
    if(iid==IID_IUnknown||iid==__uuidof(ICredentialProviderCredential)||iid==__uuidof(ICredentialProviderCredential2)) *p=static_cast<ICredentialProviderCredential2*>(this);
    if(!*p) return E_NOINTERFACE; AddRef(); return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
  ULONG STDMETHODCALLTYPE Release() override { auto n=--refs_; if(!n) delete this; return n; }
  HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents* events) override {
    UnAdvise(); events_=events; if(events_) { events_->AddRef(); events_->QueryInterface(IID_PPV_ARGS(&events2_)); } return S_OK;
  }
  HRESULT STDMETHODCALLTYPE UnAdvise() override {
    // This detaches UI callbacks during re-enumeration; it is not cancellation.
    // Explicit deselection, destruction, service revocation and expiry still cancel.
    if(events2_) {events2_->Release();events2_=nullptr;} if(events_){events_->Release();events_=nullptr;} return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetSelected(BOOL* autoLogon) override {
    if(!autoLogon) return E_POINTER; selected_=true;refresh_interaction();*autoLogon=ready();trace(L"tile selected; interaction-confirmed approval ready="+std::to_wstring(*autoLogon)); if(has_approval())return S_OK;
    try{scan(false);}catch(...){post(L"Cannot start face scan. Use Windows PIN/password.",generation_);} return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetDeselected() override {
    trace(L"tile deselected; approval ready="+std::to_wstring(ready()));
    // Windows may deselect an unselected tile while keeping PIN/password active.
    // That must not cancel an independent automatic scan. Leaving a selected
    // FacePass tile is explicit cancellation and must discard late approvals.
    const bool wasSelected=selected_;selected_=false;
    if(wasSelected) {
      stop_scan(true);
      // Cancellation ends this attempt. Keep observing future lock/resume
      // episodes if Windows retains the provider while PIN/password is active.
      start_automatic();
    }
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetFieldState(DWORD id,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override {
    if(!state||!interactive) return E_POINTER; if(id>=FieldCount) return E_INVALIDARG;
    *state=id==0||id==1 ? CPFS_DISPLAY_IN_BOTH : CPFS_DISPLAY_IN_SELECTED_TILE; *interactive=CPFIS_NONE; return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetStringValue(DWORD id,wchar_t** value) override {
    if(!value) return E_POINTER; *value=nullptr;
    if(id==1) return SHStrDupW(password_backend_enabled()?L"FacePass face unlock":passwordless_enabled()?L"FacePass passwordless unlock":L"FacePass (recognition demo)",value);
    if(id==2) return SHStrDupW(text_.c_str(),value);
    if(id==3) return SHStrDupW(L"Scan again",value);
    if(id==4) return SHStrDupW(L"Unlock",value); return E_INVALIDARG;
  }
  HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD id,HBITMAP* bitmap) override {
    if(!bitmap) return E_POINTER; *bitmap=nullptr; if(id!=0) return E_INVALIDARG;
    HDC screen=GetDC(nullptr),dc=CreateCompatibleDC(screen); HBITMAP b=CreateCompatibleBitmap(screen,96,96); ReleaseDC(nullptr,screen);
    if(!dc||!b) {if(dc)DeleteDC(dc);if(b)DeleteObject(b);return E_OUTOFMEMORY;}
    auto old=SelectObject(dc,b); RECT rect{0,0,96,96}; HBRUSH background=CreateSolidBrush(RGB(30,49,76)); FillRect(dc,&rect,background); DeleteObject(background);
    HBRUSH brush=CreateSolidBrush(RGB(121,191,238)); auto oldBrush=SelectObject(dc,brush); auto oldPen=SelectObject(dc,GetStockObject(NULL_PEN));
    Ellipse(dc,30,15,66,53); RoundRect(dc,17,55,79,90,20,20);
    SelectObject(dc,oldPen);SelectObject(dc,oldBrush);DeleteObject(brush);SelectObject(dc,old);DeleteDC(dc);*bitmap=b;return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD,BOOL* checked,wchar_t** label) override {if(checked)*checked=FALSE;if(label)*label=nullptr;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD id,DWORD* adjacent) override {if(!adjacent)return E_POINTER;*adjacent=1;return id==4?S_OK:E_INVALIDARG;}
  HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD,DWORD* count,DWORD* selected) override {if(count)*count=0;if(selected)*selected=0;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD,DWORD,wchar_t** value) override {if(value)*value=nullptr;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE SetStringValue(DWORD,const wchar_t*) override {return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD,BOOL) override {return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD,DWORD) override {return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD id) override {if(id!=3)return E_INVALIDARG;try{scan(true);}catch(...){return E_FAIL;}return S_OK;}
  HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,wchar_t** text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
    if(!response||!serialization||!text||!icon) return E_POINTER;
    *response=CPGSR_NO_CREDENTIAL_NOT_FINISHED; *serialization={}; *text=nullptr; *icon=CPSI_WARNING;
    refresh_interaction();
    trace(L"serialization requested; approval ready="+std::to_wstring(ready()));
    ULONG package=0;
    if(ready() && password_backend_enabled()) {
      try {
        if(!negotiate_package_id(package)) throw std::runtime_error("Windows Negotiate authentication is unavailable.");
        Request request;request.operation=Operation::RetrieveWindowsCredential;request.ticket=ticket_;wcscpy_s(request.targetSid,sid_.c_str());
        auto result=provider_call(request);
        trace(L"one-use approval consumed; credential received");
        serializedNonce_=ticket_.nonce;ticket_={};
        auto packed=pack_windows_credential(result.windowsCredential,unlockWorkstation_);
        struct Wipe {std::vector<BYTE>& data;~Wipe(){SecureZeroMemory(data.data(),data.size());}} wipe{packed};
        auto buffer=static_cast<BYTE*>(CoTaskMemAlloc(packed.size()));if(!buffer)return E_OUTOFMEMORY;
        std::memcpy(buffer,packed.data(),packed.size());
        serialization->ulAuthenticationPackage=package;serialization->clsidCredentialProvider=ProviderClsid;
        serialization->cbSerialization=static_cast<ULONG>(packed.size());serialization->rgbSerialization=buffer;
        *response=CPGSR_RETURN_CREDENTIAL_FINISHED;*icon=CPSI_NONE;trace(L"protected credential submitted to Windows Negotiate");return S_OK;
      } catch(const std::exception& ex) {
        trace(L"serialization failed: "+widen(ex.what()));
        ticket_={};return SHStrDupW((L"Face unlock unavailable: "+widen(ex.what())+L" Use Windows PIN/password.").c_str(),text);
      }
    }
    if(ready() && passwordless_enabled() && unlock_package_id(package)) {
      auto buffer=static_cast<UnlockLogon*>(CoTaskMemAlloc(sizeof(UnlockLogon)));
      if(!buffer)return E_OUTOFMEMORY;
      *buffer=UnlockLogon{}; buffer->ticket=ticket_; serializedNonce_=ticket_.nonce;ticket_={};
      serialization->ulAuthenticationPackage=package; serialization->clsidCredentialProvider=ProviderClsid;
      serialization->cbSerialization=sizeof(UnlockLogon); serialization->rgbSerialization=reinterpret_cast<BYTE*>(buffer);
      *response=CPGSR_RETURN_CREDENTIAL_FINISHED; *icon=CPSI_NONE; return S_OK;
    }
    return SHStrDupW(has_approval()?L"Face verified. Press Space or Enter, or interact with the lock screen to continue.":L"Wait for the face scan to finish, or select Windows PIN/password.",text);
  }
  HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS status,NTSTATUS substatus,wchar_t** text,CREDENTIAL_PROVIDER_STATUS_ICON* icon) override {
    trace(L"Windows result; status="+status_code(status)+L"; substatus="+status_code(substatus));
    stop_scan();if(text)*text=nullptr;if(icon)*icon=status<0?CPSI_ERROR:CPSI_NONE;
    if(status<0 && password_backend_enabled()) {
      // Do not repeatedly replay a stale password and risk an account lockout.
      try {Request r;r.operation=Operation::DeleteWindowsCredential;wcscpy_s(r.targetSid,sid_.c_str());provider_call(r);}catch(...){}
      if(text)return SHStrDupW(L"Windows rejected face unlock. Use your PIN/password, then save the current account password again in FacePass Settings.",text);
    }
    if(status<0 && text)return SHStrDupW(L"FacePass unlock failed. Use Windows PIN/password; select Scan again to retry.",text);return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetUserSid(wchar_t** sid) override {if(!sid)return E_POINTER;return SHStrDupW(sid_.c_str(),sid);}
};
class Provider final : public ICredentialProvider,public ICredentialProviderSetUserArray {
  std::atomic<ULONG> refs_{1}; std::vector<Credential*> credentials_;
  std::shared_ptr<Notifications> notifications_=std::make_shared<Notifications>();
  CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_=CPUS_INVALID;
  void clear(){for(auto c:credentials_)c->Release();credentials_.clear();}
public:
  Provider(){++objects;} ~Provider(){UnAdvise();clear();--objects;}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p) override {
    if(!p)return E_POINTER;*p=nullptr;
    if(iid==IID_IUnknown||iid==__uuidof(ICredentialProvider))*p=static_cast<ICredentialProvider*>(this);
    else if(iid==__uuidof(ICredentialProviderSetUserArray))*p=static_cast<ICredentialProviderSetUserArray*>(this);
    if(!*p)return E_NOINTERFACE;AddRef();return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override{return ++refs_;}
  ULONG STDMETHODCALLTYPE Release() override{auto n=--refs_;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,DWORD) override {
    if((scenario!=CPUS_LOGON&&scenario!=CPUS_UNLOCK_WORKSTATION)||GetSystemMetrics(SM_REMOTESESSION))return E_NOTIMPL; scenario_=scenario;return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override{return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* e,UINT_PTR c) override {
    if(e)e->AddRef();if(notifications_->events)notifications_->events->Release();
    notifications_->events=e;notifications_->context=c;
    if(e)for(auto credential:credentials_)credential->start_automatic();return S_OK;
  }
  HRESULT STDMETHODCALLTYPE UnAdvise() override {
    if(notifications_->events){notifications_->events->Release();notifications_->events=nullptr;}notifications_->context=0;
    for(auto credential:credentials_)credential->stop_scan(true);return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count) override {if(!count)return E_POINTER;*count=FieldCount;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD id,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override {
    if(!descriptor)return E_POINTER;*descriptor=nullptr;if(id>=FieldCount)return E_INVALIDARG;
    auto p=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));if(!p)return E_OUTOFMEMORY;
    *p={};p->dwFieldID=id;
    const CREDENTIAL_PROVIDER_FIELD_TYPE types[]={CPFT_TILE_IMAGE,CPFT_LARGE_TEXT,CPFT_SMALL_TEXT,CPFT_COMMAND_LINK,CPFT_SUBMIT_BUTTON};p->cpft=types[id];
    if(id==0)p->guidFieldType=CPFG_CREDENTIAL_PROVIDER_LOGO;
    if(id==1)p->guidFieldType=CPFG_CREDENTIAL_PROVIDER_LABEL;
    auto hr=SHStrDupW(id==1?L"FacePass":id==3?L"Scan again":id==4?L"Unlock":L"Face recognition",&p->pszLabel);
    if(FAILED(hr)){CoTaskMemFree(p);return hr;}*descriptor=p;return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* count,DWORD* selected,BOOL* automatic) override {
    if(!count||!selected||!automatic)return E_POINTER;*count=scenario_==CPUS_INVALID?0:static_cast<DWORD>(credentials_.size());*selected=CREDENTIAL_PROVIDER_NO_DEFAULT;*automatic=FALSE;
    for(DWORD i=0;i<*count;++i) {credentials_[i]->refresh_interaction();if(credentials_[i]->ready()){*selected=i;*automatic=TRUE;break;}}trace(L"credentials enumerated; automatic="+std::to_wstring(*automatic));return S_OK;
  }
  HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD id,ICredentialProviderCredential** credential) override {if(!credential)return E_POINTER;*credential=nullptr;if(id>=credentials_.size())return E_INVALIDARG;*credential=credentials_[id];(*credential)->AddRef();return S_OK;}
  HRESULT STDMETHODCALLTYPE SetUserArray(ICredentialProviderUserArray* users) override {
    if(!users)return E_POINTER;DWORD count=0;auto hr=users->GetCount(&count);if(FAILED(hr))return hr;
    try {
      std::vector<std::wstring> sids;
      for(DWORD i=0;i<count&&i<64;++i) {
        ICredentialProviderUser* user=nullptr;
        if(SUCCEEDED(users->GetAt(i,&user))) {wchar_t* sid=nullptr;hr=user->GetSid(&sid);user->Release();if(SUCCEEDED(hr)&&sid){sids.emplace_back(sid);CoTaskMemFree(sid);}}
      }
      bool same=sids.size()==credentials_.size();
      for(size_t i=0;same&&i<sids.size();++i)same=credentials_[i]->sid()==sids[i];
      if(same)return S_OK;
      clear();
      for(const auto& sid:sids) {auto c=new(std::nothrow) Credential(sid,notifications_,scenario_==CPUS_UNLOCK_WORKSTATION);if(!c){clear();return E_OUTOFMEMORY;}credentials_.push_back(c);if(notifications_->events)c->start_automatic();}
    }catch(...){clear();return E_OUTOFMEMORY;}return S_OK;
  }
};
class Factory final : public IClassFactory {
  std::atomic<ULONG> refs_{1};
public:
  Factory(){++objects;}~Factory(){--objects;}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=IID_IClassFactory)return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef() override{return ++refs_;}
  ULONG STDMETHODCALLTYPE Release() override{auto n=--refs_;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer,REFIID iid,void** p) override{if(!p)return E_POINTER;*p=nullptr;if(outer)return CLASS_E_NOAGGREGATION;auto provider=new(std::nothrow) Provider;if(!provider)return E_OUTOFMEMORY;auto hr=provider->QueryInterface(iid,p);provider->Release();return hr;}
  HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override{if(lock)++objects;else --objects;return S_OK;}
};
HRESULT set_registry(const std::wstring& path,const wchar_t* name,const std::wstring& value) {
  HKEY key=nullptr;auto error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,nullptr,0,KEY_WRITE|KEY_WOW64_64KEY,nullptr,&key,nullptr);
  if(error!=ERROR_SUCCESS)return HRESULT_FROM_WIN32(error);
  error=RegSetValueExW(key,name,0,REG_SZ,reinterpret_cast<const BYTE*>(value.c_str()),static_cast<DWORD>((value.size()+1)*sizeof(wchar_t)));RegCloseKey(key);return HRESULT_FROM_WIN32(error);
}
}
extern "C" BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void*) {if(reason==DLL_PROCESS_ATTACH){module=instance;DisableThreadLibraryCalls(instance);}return TRUE;}
extern "C" HRESULT __stdcall DllCanUnloadNow(){return objects==0?S_OK:S_FALSE;}
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid,REFIID iid,void** p) {if(!p)return E_POINTER;*p=nullptr;if(clsid!=ProviderClsid)return CLASS_E_CLASSNOTAVAILABLE;auto factory=new(std::nothrow) Factory;if(!factory)return E_OUTOFMEMORY;auto hr=factory->QueryInterface(iid,p);factory->Release();return hr;}
extern "C" HRESULT __stdcall DllUnregisterServer() {
  const auto provider=std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\")+ProviderId;
  const auto com=std::wstring(L"SOFTWARE\\Classes\\CLSID\\")+ProviderId;
  auto a=RegDeleteTreeW(HKEY_LOCAL_MACHINE,provider.c_str()),b=RegDeleteTreeW(HKEY_LOCAL_MACHINE,com.c_str());
  return (a==ERROR_SUCCESS||a==ERROR_FILE_NOT_FOUND)&&(b==ERROR_SUCCESS||b==ERROR_FILE_NOT_FOUND)?S_OK:E_ACCESSDENIED;
}
extern "C" HRESULT __stdcall DllRegisterServer() {
  wchar_t path[32768]{};if(!GetModuleFileNameW(module,path,32768))return HRESULT_FROM_WIN32(GetLastError());
  const auto com=std::wstring(L"SOFTWARE\\Classes\\CLSID\\")+ProviderId;
  auto hr=set_registry(com,nullptr,L"FacePass RGB recognition and optional face unlock");
  if(SUCCEEDED(hr))hr=set_registry(com+L"\\InprocServer32",nullptr,path);
  if(SUCCEEDED(hr))hr=set_registry(com+L"\\InprocServer32",L"ThreadingModel",L"Apartment");
  if(SUCCEEDED(hr))hr=set_registry(std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\")+ProviderId,nullptr,L"FacePass (optional face unlock)");
  if(FAILED(hr))DllUnregisterServer();return hr;
}
