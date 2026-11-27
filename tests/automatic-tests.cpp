#include "automatic-runtime.hpp"
#include "facepass/controller.hpp"
#include <wtsapi32.h>
#include <iostream>
#include <functional>
#include <map>
// Exercise the same provider implementation, with IPC/OS identity replaced only
// in this executable. Never register a provider or perform a Windows logon.
#include "../src/provider/provider.cpp"

namespace fixture {
int checks=0;
std::filesystem::path root;
const std::wstring alice=L"S-1-5-21-1-2-3-1001",bob=L"S-1-5-21-1-2-3-1002";
std::atomic<DWORD> console{7};
std::mutex osMutex;
std::map<DWORD,std::wstring> owners{{7,alice},{8,bob}};
std::atomic<bool> locked{false},backend{true},trusted{true},complete{false};
std::atomic<bool> delayStatus{false},statusWaiting{false};
std::atomic<int> captures{0},stopped{0},polls{0},recognizeRequests{0},cancellations{0};
std::atomic<Phase> result{Phase::Recognized};
std::atomic<Profile> profile{Profile::Balanced};
std::atomic<std::uint64_t> clockOffset{0};
std::atomic<DWORD> lastInput{900},inputClock{1000};
std::atomic<bool> inputAvailable{true},logonDesktop{true};
std::atomic<int> credentialReleases{0};
Controller* controller=nullptr;
void check(bool value,const char* label) {++checks;if(!value)throw std::runtime_error(label);}
void pump() {MSG message{};while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}}
void until(const std::function<bool()>& condition,const char* label) {
  const auto deadline=GetTickCount64()+3500;
  while(!condition() && GetTickCount64()<deadline){pump();Sleep(10);}
  pump();check(condition(),label);
}
Caller provider(DWORD session=console) {return {L"S-1-5-18",true,false,ClientRole::Provider,session};}
Response state(Controller& service,const std::wstring& sid=alice,DWORD session=console) {
  Request request;wcscpy_s(request.targetSid,sid.c_str());return service.handle(provider(session),request);
}
Response operation(Controller& service,Operation op,const std::wstring& sid=alice) {
  Request request;request.operation=op;wcscpy_s(request.targetSid,sid.c_str());
  if(op==Operation::Cancel)request.lockEpoch=state(service,sid).lockEpoch;return service.handle(provider(),request);
}
void configure(Controller& service,Mode mode,Profile recognition=Profile::Instant) {
  Request request;request.operation=Operation::Configure;request.config.mode=mode;request.config.profile=recognition;request.config.timeoutSeconds=5;
  check(!service.handle({alice,false,true},request).error,"own-account activation configuration succeeds");
}
void unlock(Controller& service) {locked=false;service.session_event(WTS_SESSION_UNLOCK,console);}
void lock(Controller& service) {complete=false;locked=true;service.session_event(WTS_SESSION_LOCK,console);}
void idle(Controller& service,const std::wstring& sid=alice) {until([&]{return !state(service,sid).cameraActive;},"capture stops and camera becomes idle");}
void interact() {lastInput=inputClock.fetch_add(20)+20;}
void prepare() {
  Store store(root,false);Config config;config.mode=Mode::Automatic;config.profile=Profile::Instant;config.timeoutSeconds=5;
  Template face;face.samples.resize(SampleCount);for(auto& sample:face.samples)sample[0]=1;
  for(const auto& sid:{alice,bob}) {
    store.config(sid,config);store.save(sid,face);
    WindowsCredential credential;credential.version=1;wcscpy_s(credential.sid,sid.c_str());
    wcscpy_s(credential.username,L"MicrosoftAccount\\fixture@example.test");wcscpy_s(credential.password,L"Synthetic test credential only");
    store.credential(sid,credential);
  }
}
}
namespace facepass::testing {
std::filesystem::path store_root(){return fixture::root;}
DWORD console_session(){return fixture::console;}
std::wstring session_owner(DWORD session){std::lock_guard lock(fixture::osMutex);auto it=fixture::owners.find(session);return it==fixture::owners.end()?L"":it->second;}
bool session_locked(DWORD){return fixture::locked;}
bool backend_available(){return fixture::backend;}
bool password_backend_enabled(){return fixture::backend;}
CaptureResult capture(CaptureKind,const Config& config,const Template&,std::stop_token stop,const Progress& progress,const PreviewSink&) {
  fixture::profile=config.profile; ++fixture::captures;
  if(progress)progress({Phase::Capturing,0,0,L"Synthetic capture running"});
  while(!stop.stop_requested() && !fixture::complete)Sleep(2);
  ++fixture::stopped;
  return {{stop.stop_requested()?Phase::Cancelled:fixture::result.load(),0.9f,100,L"Synthetic capture finished"},{}};
}
bool trusted_provider(){return fixture::trusted;}
std::uint64_t provider_now(){return unix_millis()+fixture::clockOffset;}
std::optional<DWORD> last_input_tick(){return fixture::inputAvailable?std::optional<DWORD>(fixture::lastInput.load()):std::nullopt;}
DWORD input_now(){return fixture::inputClock;}
bool on_logon_input_desktop(){return fixture::logonDesktop;}
Response provider_request(const Request& request,std::stop_token stop) {
  if(stop.stop_requested())throw std::runtime_error("Test IPC cancelled");
  if(request.operation==Operation::Status)++fixture::polls;
  if(request.operation==Operation::Recognize)++fixture::recognizeRequests;
  if(request.operation==Operation::Cancel)++fixture::cancellations;
  if(request.operation==Operation::RetrieveWindowsCredential)++fixture::credentialReleases;
  auto response=fixture::controller->handle(fixture::provider(),request);
  if(request.operation==Operation::Status && fixture::delayStatus) {
    fixture::statusWaiting=true;
    while(fixture::delayStatus && !stop.stop_requested())Sleep(2);
  }
  if(response.error)throw std::runtime_error(narrow(response.message));return response;
}
}
namespace {
using namespace fixture;
class User final:public ICredentialProviderUser {
  std::atomic<ULONG> refs{1};
public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=__uuidof(ICredentialProviderUser))return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE GetSid(wchar_t** sid)override{return SHStrDupW(alice.c_str(),sid);}
  HRESULT STDMETHODCALLTYPE GetProviderID(GUID* id)override{if(!id)return E_POINTER;*id=GUID_NULL;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetStringValue(REFPROPERTYKEY,wchar_t** text)override{if(text)*text=nullptr;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY,PROPVARIANT* value)override{if(value)*value={};return E_NOTIMPL;}
};
class Users final:public ICredentialProviderUserArray {
  std::atomic<ULONG> refs{1};
public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=__uuidof(ICredentialProviderUserArray))return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetProviderFilter(REFGUID)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options)override{if(!options)return E_POINTER;*options=CPAO_NONE;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetCount(DWORD* count)override{if(!count)return E_POINTER;*count=1;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetAt(DWORD index,ICredentialProviderUser** user)override{if(!user)return E_POINTER;*user=nullptr;if(index)return E_INVALIDARG;*user=new User;return S_OK;}
};
class Events final:public ICredentialProviderEvents {
  std::atomic<ULONG> refs{1};
  DWORD thread=GetCurrentThreadId();
public:
  int notifications=0;
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=__uuidof(ICredentialProviderEvents))return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE CredentialsChanged(UINT_PTR context)override{check(thread==GetCurrentThreadId() && context==77,"re-enumeration callback runs on COM/UI thread with advised context");++notifications;return S_OK;}
};
struct Host {
  Provider* provider=new Provider;
  Events* events=new Events;
  ICredentialProviderCredential* credential=nullptr;
  Host() {
    check(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON,0)),"Windows 10+ logon usage accepted for console unlock");
    check(SUCCEEDED(provider->Advise(events,77)),"provider is advised before user enumeration");
    enumerate();check(SUCCEEDED(provider->GetCredentialAt(0,&credential)),"face credential enumerated");
  }
  void enumerate(){auto users=new Users;check(SUCCEEDED(provider->SetUserArray(users)),"user array enumeration succeeds");users->Release();}
  bool ready() {DWORD count=0,index=0;BOOL automatic=FALSE;provider->GetCredentialCount(&count,&index,&automatic);check(count==1,"native user retains manual FacePass tile");return automatic&&index==0;}
  void fallback(){DWORD count=0,index=0;BOOL automatic=TRUE;provider->GetCredentialCount(&count,&index,&automatic);check(count==1 && index==CREDENTIAL_PROVIDER_NO_DEFAULT && !automatic,"FacePass requests no default or submission while unapproved; native fallback is untouched");}
  bool verified() {
    wchar_t* text=nullptr;credential->GetStringValue(2,&text);
    const bool waiting=text&&std::wstring_view(text).starts_with(L"Face verified. Press Space");CoTaskMemFree(text);return waiting;
  }
  void confirm(const char* label) {
    until([&]{return verified();},"face approval waits for lock-screen interaction");
    fallback();serialize(false);const auto previous=events->notifications;interact();
    until([&]{return events->notifications==previous+1;},label);
  }
  void serialize(bool expected) {
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION packed{};wchar_t* text=nullptr;CREDENTIAL_PROVIDER_STATUS_ICON icon{};
    check(SUCCEEDED(credential->GetSerialization(&response,&packed,&text,&icon)),"existing serialization call succeeds");
    if(expected && response!=CPGSR_RETURN_CREDENTIAL_FINISHED) {
      const auto problem=text?narrow(text):std::string("no status text");CoTaskMemFree(text);
      throw std::runtime_error("Approved serialization failed: "+problem);
    }
    ULONG package=0;const bool negotiate=negotiate_package_id(package);
    check(expected?(response==CPGSR_RETURN_CREDENTIAL_FINISHED&&packed.rgbSerialization&&packed.cbSerialization&&negotiate&&packed.ulAuthenticationPackage==package):(response==CPGSR_NO_CREDENTIAL_NOT_FINISHED&&!packed.rgbSerialization),expected?"approved credential uses existing Windows Negotiate packing":"no approval produces no Windows credential");
    if(packed.rgbSerialization){SecureZeroMemory(packed.rgbSerialization,packed.cbSerialization);CoTaskMemFree(packed.rgbSerialization);}CoTaskMemFree(text);
  }
  ~Host(){provider->UnAdvise();if(credential)credential->Release();provider->Release();events->Release();pump();}
};
void service_tests() {
  Controller service(false,{});controller=&service;
  lock(service);check(captures==0 && !state(service).unlockEligible,"startup lock cannot manufacture native sign-in provenance");
  unlock(service);lock(service);until([]{return captures==1;},"WTS lock starts automatic capture without any provider or tile selection");
  check(state(service).automaticAttempted && state(service).cameraActive,"service publishes the automatic attempt");
  Request wrongCancel;wrongCancel.operation=Operation::Cancel;wcscpy_s(wrongCancel.targetSid,alice.c_str());
  check(service.handle(provider(8),wrongCancel).error==ERROR_ACCESS_DENIED && state(service).cameraActive,"another session cannot cancel the active account's camera scan");
  complete=true;idle(service);auto ticket=state(service).ticket;check(valid_ticket(ticket,unix_millis()),"successful automatic recognition produces the existing session-bound approval");
  service.session_event(WTS_SESSION_LOCK,7);state(service);check(captures==1,"duplicate locks and polls preserve one attempt per screen");
  Request consume;consume.operation=Operation::RetrieveWindowsCredential;consume.ticket=ticket;wcscpy_s(consume.targetSid,alice.c_str());
  check(service.handle(provider(8),consume).error==ERROR_ACCESS_DENIED,"other session cannot release the saved credential");
  check(service.handle({alice,false,true},consume).error==ERROR_ACCESS_DENIED,"ordinary account cannot release credentials");
  check(!service.handle(provider(),consume).error && service.handle(provider(),consume).error==ERROR_ACCESS_DENIED,"one-use approval follows unchanged password-release flow");
  configure(service,Mode::Manual,Profile::Balanced);unlock(service);lock(service);check(captures==1,"Manual mode does not capture on lock");
  check(!operation(service,Operation::Recognize).error,"manual recognition remains available");until([]{return captures==2;},"manual scan starts");check(profile==Profile::Strict,"manual unlock retains Strict backend recognition policy");complete=true;idle(service);
  configure(service,Mode::Off);unlock(service);lock(service);check(captures==2 && operation(service,Operation::Recognize).error==ERROR_ACCESS_DISABLED_BY_POLICY,"Off prohibits both automatic and manual scanning");
  configure(service,Mode::Automatic);unlock(service);lock(service);until([]{return captures==3;},"next lock starts a fresh automatic attempt");
  operation(service,Operation::Cancel);idle(service);check(!state(service).ticket.version && captures==3,"cancellation revokes approval and prevents automatic retry on the same screen");
  const auto cancelledEpoch=state(service).lockEpoch;
  service.power_event(PBT_APMSUSPEND);check(!state(service).unlockEligible,"suspend disables eligibility and revokes approvals");
  service.power_event(PBT_APMRESUMEAUTOMATIC);until([]{return captures==4;},"resume starts a fresh scan for an OS-locked previously authenticated session");
  Request staleCancel;staleCancel.operation=Operation::Cancel;staleCancel.lockEpoch=cancelledEpoch;wcscpy_s(staleCancel.targetSid,alice.c_str());
  check(service.handle(provider(),staleCancel).error==ERROR_ACCESS_DENIED && state(service).cameraActive,"delayed old-screen cancellation cannot stop the new resume scan");
  service.power_event(PBT_APMRESUMESUSPEND);check(captures==4,"duplicate resume notification does not restart capture");
  service.power_event(PBT_APMSUSPEND);idle(service);check(!state(service).ticket.version,"suspend cancels active capture and suppresses late approval");
  service.power_event(PBT_APMRESUMEAUTOMATIC);until([]{return captures==5;},"capture can recover after another resume");
  console=8;service.session_event(WTS_CONSOLE_DISCONNECT,7);idle(service);check(!state(service,alice,7).unlockEligible && !state(service,alice,7).ticket.version,"disconnect revokes the old session after active console has changed");
  unlock(service);lock(service);until([]{return captures==6;},"new user uses their own native session and enrolled profile");
  check(state(service,bob).cameraActive && !state(service,alice).cameraActive,"capture belongs only to the active account");
  complete=true;idle(service,bob);check(std::wstring(state(service,bob).ticket.sid)==bob,"new user's approval is bound to their SID");
  service.session_event(WTS_SESSION_LOGOFF,8);console=7;service.session_event(WTS_CONSOLE_CONNECT,7);check(!state(service).unlockEligible,"reconnecting a disconnected account still requires native authentication");
  unlock(service);result=Phase::Rejected;lock(service);until([]{return captures==7;},"fresh native unlock permits the next lock scan");complete=true;idle(service);check(!state(service).ticket.version && captures==7,"unknown/failed recognition issues no approval or retry loop");
  result=Phase::Error;unlock(service);lock(service);until([]{return captures==8;},"next lock permits a bounded new attempt");complete=true;idle(service);check(!state(service).ticket.version && captures==8,"capture timeout/error leaves fallback available");
  result=Phase::Recognized;unlock(service);lock(service);until([]{return captures==9;},"recovery from a failed scan");service.session_event(WTS_SESSION_DESKTOP_READY,7);idle(service);check(!state(service).ticket.version && !state(service).unlockEligible,"leaving sign-in for the desktop cancels capture");
  backend=false;unlock(service);lock(service);until([]{return captures==10;},"diagnostic-only automatic mode remains available");complete=true;idle(service);check(!state(service).ticket.version,"diagnostic match is never promoted to Windows authorization");backend=true;
}
void provider_tests() {
  Controller service(false,{});controller=&service;configure(service,Mode::Automatic);unlock(service);
  {
    const auto before=captures.load(),requests=recognizeRequests.load(),previousPolls=polls.load(),cancelled=cancellations.load();
    Host host;until([&]{return polls>previousPolls;},"automatic monitoring starts without SetSelected");host.fallback();host.credential->SetDeselected();
    check(cancellations==cancelled,"unselected tile deselection does not cancel independent monitoring");
    lock(service);until([&]{return captures==before+1;},"provider advised before WTS lock survives the startup race");
    host.enumerate();ICredentialProviderCredential* again=nullptr;host.provider->GetCredentialAt(0,&again);check(again==host.credential,"re-enumeration preserves the live face credential");again->Release();
    host.credential->UnAdvise();host.provider->Advise(host.events,77);check(captures==before+1,"credential callback detachment and repeated Advise do not restart capture");
    interact();complete=true;until([&]{return host.verified();},"automatic face match waits for input instead of requesting sign-in");
    const auto releases=credentialReleases.load();host.fallback();host.serialize(false);
    Sleep(150);pump();check(host.events->notifications==0&&credentialReleases==releases,"input before face verification and idle time cannot submit credentials");
    lastInput=inputClock.load()+100;host.fallback();host.serialize(false);
    lastInput=inputClock.load()-1;host.fallback();host.serialize(false);
    check(host.events->notifications==0,"future and stale input timestamps cannot confirm a face match");
    inputAvailable=false;interact();host.fallback();host.serialize(false);inputAvailable=true;host.fallback();
    check(host.events->notifications==0,"failed input queries fail closed and recovery requires a fresh interaction");
    logonDesktop=false;interact();host.fallback();host.serialize(false);logonDesktop=true;host.fallback();
    check(host.events->notifications==0,"activity off the active Winlogon desktop cannot request sign-in");
    const auto approval=state(service).ticket;host.enumerate();host.provider->Advise(host.events,77);
    check(state(service).ticket.nonce==approval.nonce && captures==before+1,"re-enumeration and repeated Advise preserve the approval while waiting for input");
    interact();until([&]{return host.events->notifications==1;},"post-verification lock-screen input requests Windows sign-in");
    check(host.ready() && recognizeRequests==requests,"both face approval and later input gate the sign-in default independently of tile selection");
    check(stopped==captures,"camera has stopped before Windows credential serialization");host.serialize(true);host.serialize(false);
    check(credentialReleases==releases+1,"only interaction-confirmed serialization releases the one-use saved credential");
    Sleep(300);pump();check(host.events->notifications==1,"one approval requests enumeration once");
  }
  {
    unlock(service);lock(service);Host host;until([&]{return state(service).cameraActive;},"capture starts before retained-provider resume test");
    result=Phase::Rejected;complete=true;idle(service);Sleep(300);pump();host.fallback();
    check(host.events->notifications==0,"failed recognition leaves the advised automatic provider watching without submission");
    const auto before=captures.load();result=Phase::Recognized;complete=false;
    service.power_event(PBT_APMSUSPEND);service.power_event(PBT_APMRESUMEAUTOMATIC);
    until([&]{return captures==before+1;},"resume starts fresh capture while the same provider remains advised");
    complete=true;host.confirm("retained provider submits resume approval only after new input");host.serialize(true);
    unlock(service);lock(service);until([&]{return captures==before+2;},"next lock reuses the same provider with a new face scan");
    complete=true;host.confirm("the next face approval needs another interaction instead of reusing old confirmation");host.serialize(true);
  }
  {
    unlock(service);lock(service);const auto before=captures.load();Host host;until([&]{return state(service).cameraActive&&captures>=before;},"background scan is running");
    BOOL automatic=TRUE;host.credential->SetSelected(&automatic);check(!automatic,"selection cannot submit an unfinished face scan");const auto started=captures.load();
    host.credential->SetDeselected();idle(service);pump();host.fallback();check(captures==started && !state(service).ticket.version,"leaving a selected face tile cancels without late submission");
    host.credential->SetSelected(&automatic);host.credential->CommandLinkClicked(3);until([&]{return captures==started+1;},"Scan again preserves explicit manual retry in Automatic mode");
    complete=true;host.confirm("manual retry obtains approval and waits for subsequent input");host.serialize(true);
  }
  {
    unlock(service);lock(service);Host host;until([&]{return state(service).cameraActive;},"capture starts before selected-tile cancellation/resume test");
    BOOL automatic=FALSE;host.credential->SetSelected(&automatic);host.credential->SetDeselected();idle(service);host.fallback();
    const auto before=captures.load();check(!state(service).ticket.version,"selected-tile cancellation revokes the current approval");
    service.power_event(PBT_APMSUSPEND);service.power_event(PBT_APMRESUMEAUTOMATIC);
    until([&]{return captures==before+1;},"next resume may activate after a cancelled face attempt");complete=true;
    host.confirm("provider observes future resume and waits for fresh input after cancellation");host.serialize(true);
  }
  {
    unlock(service);lock(service);Host host;until([&]{return state(service).cameraActive;},"capture active before provider teardown");
    host.provider->UnAdvise();idle(service);complete=true;pump();host.fallback();check(host.events->notifications==0,"provider UnAdvise stops capture and discards queued completion messages");
    host.provider->Advise(host.events,77);Sleep(300);pump();check(!state(service).cameraActive,"re-advising the same cancelled screen does not restart capture");
  }
  {
    unlock(service);lock(service);Host host;complete=true;until([&]{return host.verified();},"new lock produces a waiting face approval");
    clockOffset=11000;interact();host.fallback();host.serialize(false);check(host.events->notifications==0,"input after approval expiry cannot request sign-in");host.provider->UnAdvise();clockOffset=0;
    check(!state(service).ticket.version,"expired or cancelled approval cannot be replayed");
  }
  {
    configure(service,Mode::Manual);unlock(service);lock(service);const auto before=captures.load();Host host;Sleep(100);pump();host.fallback();check(captures==before,"Manual provider load does not activate capture");
    BOOL automatic=FALSE;host.credential->SetSelected(&automatic);until([&]{return captures==before+1;},"Manual selection retains existing capture behavior");complete=true;
    until([&]{return host.verified();},"selected manual tile displays the waiting-for-input message");
    automatic=TRUE;host.credential->SetSelected(&automatic);check(!automatic,"Windows selecting a verified tile is not itself interaction confirmation");
    host.confirm("manual selection submits only after later lock-screen input");host.serialize(true);
  }
  {
    configure(service,Mode::Automatic);unlock(service);lock(service);inputClock=0xfffffff0;lastInput=0xffffff00;
    Host host;complete=true;host.confirm("post-verification input across uptime tick rollover still confirms exactly once");host.serialize(true);
    inputClock=1000;lastInput=900;
  }
  {
    configure(service,Mode::Manual);unlock(service);lock(service);const auto before=captures.load();statusWaiting=false;delayStatus=true;
    Host host;until([]{return statusWaiting.load();},"initial provider mode query can be delayed");
    BOOL automatic=TRUE;host.credential->SetSelected(&automatic);check(!automatic,"selection while querying mode does not submit unapproved credentials");
    delayStatus=false;until([&]{return captures==before+1;},"manual selection during the initial automatic probe still starts recognition");
    host.credential->SetDeselected();idle(service);host.fallback();
  }
  {
    configure(service,Mode::Automatic);unlock(service);lock(service);Host host;until([&]{return state(service).cameraActive;},"automatic capture active before Off");configure(service,Mode::Off);idle(service);pump();host.fallback();host.serialize(false);
    check(host.events->notifications==0,"Off cancels capture and prevents authentication");
  }
  {
    trusted=false;configure(service,Mode::Manual);unlock(service);lock(service);const auto before=polls.load();Host host;BOOL automatic=FALSE;host.credential->SetSelected(&automatic);Sleep(100);pump();check(polls==before,"untrusted process cannot activate provider IPC");host.serialize(false);trusted=true;
  }
  check(DllCanUnloadNow()==S_OK,"all COM objects, message windows and worker lifetimes are released");
}
}
int wmain() {
  try {
    fixture::root=executable_dir()/L"test-output"/(L"automatic-"+std::to_wstring(GetCurrentProcessId()));
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);DllMain(GetModuleHandleW(nullptr),DLL_PROCESS_ATTACH,nullptr);
    prepare();service_tests();provider_tests();CoUninitialize();
    for(const auto& entry:std::filesystem::directory_iterator(root))std::filesystem::remove(entry.path());std::filesystem::remove(root);
    std::cout<<"PASS: "<<checks<<" automatic/provider/session checks (simulated capture; no Windows logon or registration)\n";return 0;
  } catch(const std::exception& ex){std::cerr<<"FAILED: "<<ex.what()<<" (after "<<checks<<" checks)\n";return 1;}
}
