#include "facepass/vision.hpp"
#include "facepass/storage.hpp"
#include "facepass/ipc.hpp"
#include "facepass/capture.hpp"
#include <credentialprovider.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <limits>
#include <atomic>
#include <wincred.h>
#define SECURITY_WIN32
#include <security.h>
using namespace facepass;
namespace {
int checks=0;
void check(bool condition,const char* label){++checks;if(!condition)throw std::runtime_error(std::string("FAILED: ")+label);}
template<class F>void rejects(F action,const char* label){bool thrown=false;try{action();}catch(...){thrown=true;}check(thrown,label);}
Embedding basis(unsigned index){Embedding e{};e[index]=1;return e;}
void core_tests() {
  Config c;check(valid_config(c),"defaults valid");c.threshold=std::numeric_limits<float>::quiet_NaN();check(!valid_config(c),"NaN threshold rejected");c={};c.mode=static_cast<Mode>(42);check(!valid_config(c),"unknown activation rejected");
  c={};c.profile=Profile::Instant;check(valid_config(c),"Instant profile is valid");c.profile=static_cast<Profile>(4);check(!valid_config(c),"unknown recognition profile rejected");
  for(auto profile:{Profile::Convenience,Profile::Balanced,Profile::Strict}) {
    c={};c.profile=profile;auto effective=unlock_config(c);
    check(effective.profile==Profile::Strict&&effective.threshold==0.55f,"existing Windows unlock profiles still require Strict and its threshold");
  }
  c={};c.profile=Profile::Instant;c.threshold=0.50f;auto effective=unlock_config(c);
  check(effective.profile==Profile::Instant&&effective.threshold==c.threshold,"Windows unlock preserves explicit Instant and configured face threshold");
  c.profile=Profile::Balanced;c.threshold=0.70f;check(unlock_config(c).threshold==0.70f,"Windows unlock preserves a stricter configured threshold");
  c={};c.attempts=3;c.cooldownSeconds=30;RetryPolicy policy;auto now=std::chrono::steady_clock::now();
  check(policy.allowed(now),"initial retry allowed");policy.failed(c,now);policy.failed(c,now);check(policy.allowed(now),"retry limit not reached");policy.failed(c,now);check(!policy.allowed(now),"cooldown after three failures");check(policy.allowed(now+std::chrono::seconds(31)),"cooldown expiration");policy.failed(c,now+std::chrono::seconds(31));check(policy.allowed(now+std::chrono::seconds(31)),"failure counter resets after cooldown");policy.succeeded();check(policy.remaining(now)==0,"success resets policy");
  check(cosine(basis(0),basis(0))>0.99,"same identity matches");check(cosine(basis(0),basis(1))==0,"unknown identity rejected");check(cosine(Embedding{},basis(0))<0,"zero embeddings rejected");
  Template t;t.samples={basis(0),basis(1),basis(1),basis(1),basis(1),basis(1),basis(1)};check(match(basis(0),t)==0,"single poisoned enrollment sample cannot match");
  Hello hello;hello.expires=unix_millis()+2000;random_bytes(hello.nonce);Request request;request.nonce=hello.nonce;
  check(valid_request(hello,request,unix_millis()),"fresh nonce accepted");auto replay=request;replay.nonce[0]^=1;check(!valid_request(hello,replay,unix_millis()),"replay/wrong nonce rejected");check(!valid_request(hello,request,hello.expires+1),"expired request rejected");request.operation=static_cast<Operation>(999);check(!valid_request(hello,request,unix_millis()),"unknown operation rejected");request.operation=Operation::Status;std::fill(std::begin(request.targetSid),std::end(request.targetSid),L'x');check(!valid_request(hello,request,unix_millis()),"unterminated SID rejected");
  Caller user{L"S-1-5-21-1-2-3-1001",false,false},system{L"S-1-5-18",true,false,ClientRole::Provider,1};
  check(!authorize(user,Operation::Enroll,L""),"unauthenticated enrollment rejected");user.fresh=true;check(authorize(user,Operation::Enroll,user.sid),"fresh own-account enrollment accepted");check(!authorize(user,Operation::Enroll,L"S-1-5-21-1-2-3-1002"),"cross-account enrollment rejected");check(!authorize(system,Operation::Configure,user.sid),"provider cannot change config");check(!authorize(system,Operation::Enroll,user.sid),"provider cannot enroll");check(authorize(system,Operation::Recognize,user.sid),"provider may request recognition only");
  Liveness balanced(Profile::Balanced,{-1,0});Observation o{};bool passed=false;
  for(int i=0;i<100;++i)passed|=balanced.update(o,now+std::chrono::seconds(3));check(!passed,"static portrait fails active challenge");
  for(int i=0;i<3;++i){o.yaw=-0.3f;balanced.update(o,now+std::chrono::seconds(3));}for(int i=0;i<3;++i){o.yaw=0;passed=balanced.update(o,now+std::chrono::seconds(4));}check(passed,"ordered balanced challenge observed");
  Liveness strict(Profile::Strict,{1,0,-1,0});for(float yaw:{0.3f,0.0f,-0.3f,0.0f})for(int i=0;i<3;++i){o.yaw=yaw;passed=strict.update(o,now+std::chrono::seconds(4));}check(passed,"strict four-step challenge observed");
  Liveness minimumTime(Profile::Balanced,{-1,0});auto instantTime=std::chrono::steady_clock::now();
  for(float yaw:{-0.3f,0.0f})for(int i=0;i<3;++i){o.yaw=yaw;passed=minimumTime.update(o,instantTime);}
  check(!passed&&!minimumTime.update(o,instantTime),"completed pose sequence cannot bypass minimum challenge time");
  Liveness instant(Profile::Instant);o.yaw=0;check(instant.update(o,instantTime),"Instant skips poses and minimum liveness duration");
  c={};c.profile=Profile::Instant;c.threshold=0.50f;RecognitionGate instantGate(unlock_config(c));
  t.samples.assign(SampleCount,basis(0));o.embedding=basis(1);
  check(!instantGate.update(o,match(o.embedding,t),instantTime),"Instant still rejects an unknown 2D face");
  o.embedding=basis(0);check(instantGate.update(o,match(o.embedding,t),instantTime),"first matching frame immediately satisfies Instant unlock");
  check(!instantGate.update(o,0.499f,instantTime),"Instant rejects a score below the saved threshold");
  check(instantGate.update(o,0.50f,instantTime),"Instant accepts the exact saved threshold without waiting");
  check(!instantGate.update(o,std::numeric_limits<float>::quiet_NaN(),instantTime),"invalid similarity cannot satisfy Instant");
  instantGate.reset();check(instantGate.update(o,0.50f,instantTime),"first match after reset still satisfies Instant without accumulated frames");
  c.profile=Profile::Convenience;RecognitionGate temporalGate(c);passed=false;
  for(int i=0;i<12;++i)passed|=temporalGate.update(o,1.0f,instantTime);
  check(!passed,"Convenience still enforces its minimum wait");
  check(temporalGate.update(o,1.0f,instantTime+std::chrono::seconds(2)),"Convenience accepts stable matching frames after its minimum wait");
  temporalGate.reset();passed=false;
  for(int i=0;i<9;++i)passed|=temporalGate.update(o,1.0f,instantTime+std::chrono::seconds(2));
  check(!passed,"reset restarts the existing stable-frame requirement");
  check(!temporalGate.update(o,0.0f,instantTime+std::chrono::seconds(2)),"mismatch resets an existing temporal scan");
  check(!temporalGate.update(o,1.0f,instantTime+std::chrono::seconds(2)),"matching frame after mismatch cannot reuse earlier stability");
  for(auto profile:{Profile::Balanced,Profile::Strict}) {
    c.profile=profile;RecognitionGate activeGate(c);passed=false;
    for(int i=0;i<30;++i)passed|=activeGate.update(o,1.0f,instantTime+std::chrono::seconds(4));
    check(!passed,"existing active profiles still reject static matching portraits");
  }
  check(!DiagnosticRecognition::available(),"diagnostic scans cannot authorize Windows unlock");
  UnlockGrants grants; auto ticket=grants.issue(user.sid,1);
  check(valid_ticket(ticket,unix_millis()),"valid passwordless authorization");
  check(grants.peek(user.sid,2).version==0,"unlock ticket is session-bound");
  auto forged=ticket; forged.nonce[0]^=1;
  check(!grants.consume(forged),"forged ticket cannot authorize unlock");
  check(grants.consume(ticket),"matching one-use ticket accepted");
  check(!grants.consume(ticket),"unlock replay refused");
  ticket=grants.issue(user.sid,1); auto expired=ticket; expired.expires=unix_millis()-1;
  check(!grants.consume(expired),"expired authorization refused");
  grants.revoke(user.sid); check(!grants.consume(ticket),"cancellation revokes unlock");
  ticket=grants.issue(user.sid,1); auto replacement=grants.issue(user.sid,1);
  check(!grants.consume(ticket)&&grants.consume(replacement),"new scan revokes earlier authorization");
  auto empty=replacement; empty.nonce={};check(!valid_ticket(empty,unix_millis()),"empty unlock nonce refused");
  Caller authority{L"S-1-5-18",true,false,ClientRole::Authority,0};
  check(authorize(authority,Operation::ConsumeUnlock,user.sid),"authority may consume unlock");
  check(!authorize(user,Operation::ConsumeUnlock,user.sid)&&!authorize(system,Operation::ConsumeUnlock,user.sid),"users and provider cannot consume unlock");
  check(!authorize({L"S-1-5-18",true,false},Operation::Recognize,user.sid),"unclassified SYSTEM process cannot request unlock");
  check(!authorize(user,Operation::RetrieveWindowsCredential,user.sid),"ordinary users cannot retrieve saved passwords");
  check(!authorize(authority,Operation::RetrieveWindowsCredential,user.sid),"LSASS cannot use the provider password-release path");
  check(authorize(system,Operation::RetrieveWindowsCredential,user.sid),"only trusted provider role may request password release");
  user.fresh=false;check(!authorize(user,Operation::SaveWindowsCredential,L""),"saving passwords requires fresh OS authentication");
  user.fresh=true;check(authorize(user,Operation::SaveWindowsCredential,L""),"verified own-account credential setup permitted");
  check(!authorize(system,Operation::SaveWindowsCredential,user.sid),"provider cannot replace a user's saved password");
  rejects([&]{grants.issue(L"S-1-5-18",1);},"system identity cannot obtain a face ticket");
  auto root=std::filesystem::current_path()/L"test-output"/(L"store-"+std::to_wstring(GetCurrentProcessId()));
  Store store(root,false);auto sid=current_sid();c={};c.mode=Mode::Manual;store.config(sid,c);check(store.config(sid).mode==Mode::Manual,"encrypted config persists");
  c.profile=Profile::Instant;store.config(sid,c);check(store.config(sid).profile==Profile::Instant,"encrypted Instant preference persists");
  WindowsCredential saved;saved.version=1;wcscpy_s(saved.sid,sid.c_str());wcscpy_s(saved.username,L"MicrosoftAccount\\facepass-test@example.test");wcscpy_s(saved.password,L"Synthetic-test-secret-42!");
  check(valid_windows_credential(saved),"bounded Microsoft identity credential accepted");
  check(microsoft_account_username(L"facepass-test@example.test")==saved.username,"bare Microsoft-account email gains its provider namespace before verification");
  check(microsoft_account_username(saved.username)==saved.username,"qualified Microsoft-account username remains qualified once");
  check(microsoft_account_username(L"facepass-test@example.test",L"MicrosoftAccount")==saved.username,"split CredUI username and provider domain are normalized");
  rejects([]{microsoft_account_username(L"facepass-test@example.test",L"AzureAD");},"other account domains are not silently converted to Microsoft accounts");
  rejects([]{microsoft_account_username(L"AzureAD\\facepass-test@example.test");},"other qualified identity providers rejected before authentication");
  rejects([]{microsoft_account_username(L"MicrosoftAccount\\");},"empty Microsoft identity rejected before authentication");
  rejects([]{microsoft_account_username(L"MicrosoftAccount\\one\\two");},"nested provider names rejected before authentication");
  rejects([]{microsoft_account_username(L"local-user");},"unqualified local names are not treated as Microsoft accounts");
  rejects([]{microsoft_account_username(std::wstring(512,L'x')+L"@test");},"overlong identity rejected before authentication");
  auto invalid=saved;wcscpy_s(invalid.username,L"AzureAD\\facepass-test@example.test");check(!valid_windows_credential(invalid),"other identity providers rejected");
  invalid=saved;std::fill(std::begin(invalid.password),std::end(invalid.password),L'x');check(!valid_windows_credential(invalid),"unterminated password rejected");
  store.credential(sid,saved);check(store.credential_saved(sid),"credential file persists");
  auto restored=store.credential(sid);check(wcscmp(restored.password,saved.password)==0&&wcscmp(restored.username,saved.username)==0,"encrypted credential round-trip");
  auto credentialFile=root/(sid+L".credential");
  {std::ifstream stream(credentialFile,std::ios::binary);std::vector<char> data((std::istreambuf_iterator<char>(stream)),{});auto first=reinterpret_cast<const char*>(saved.password);auto count=wcslen(saved.password)*sizeof(wchar_t);check(std::search(data.begin(),data.end(),first,first+count)==data.end(),"disk credential contains no plaintext password");}
  const std::wstring otherSid=L"S-1-5-21-1-2-3-1234";
  rejects([&]{store.credential(otherSid,saved);},"cross-account credential writes rejected");
  auto copiedFile=root/(otherSid+L".credential");std::filesystem::copy_file(credentialFile,copiedFile);
  rejects([&]{store.credential(otherSid);},"copied encrypted credentials remain bound to their original SID");std::filesystem::remove(copiedFile);
  ULONG negotiate=0;check(negotiate_package_id(negotiate),"built-in Windows Negotiate package available without custom LSA registration");
  auto packed=pack_windows_credential(saved);
  {auto first=reinterpret_cast<const BYTE*>(saved.password);auto count=wcslen(saved.password)*sizeof(wchar_t);check(std::search(packed.begin(),packed.end(),first,first+count)==packed.end(),"serialization protects the password in the caller logon session");}
  check(SspiValidateAuthIdentity(packed.data())==SEC_E_OK&&SspiIsAuthIdentityEncrypted(packed.data()),"Windows recognizes the serialized identity as valid and encrypted");
  auto decrypted=packed;
  auto sspi=LoadLibraryExW(L"sspicli.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
  struct SspiModule {HMODULE value;~SspiModule(){if(value)FreeLibrary(value);}} freeSspi{sspi};
  auto decrypt=sspi?reinterpret_cast<decltype(&SspiDecryptAuthIdentityEx)>(GetProcAddress(sspi,"SspiDecryptAuthIdentityEx")):nullptr;
  check(decrypt&&decrypt(SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_LOGON,decrypted.data())==SEC_E_OK,"Windows decrypts the identity in the originating logon session");
  {auto first=reinterpret_cast<const BYTE*>(saved.password);auto count=wcslen(saved.password)*sizeof(wchar_t);check(std::search(decrypted.begin(),decrypted.end(),first,first+count)!=decrypted.end(),"Windows recovers the exact synthetic password from protected serialization");}
  SecureZeroMemory(decrypted.data(),decrypted.size());
  wchar_t unpackedUser[513]{},unpackedDomain[513]{},unpackedPassword[513]{};DWORD us=513,ds=513,ps=513;
  check(CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,packed.data(),static_cast<DWORD>(packed.size()),unpackedUser,&us,unpackedDomain,&ds,unpackedPassword,&ps)!=FALSE,"Windows unpacks the protected online identity credential");
  // EX2 unpacking returns a marshaled credential string rather than a plain password.
  SecureZeroMemory(unpackedPassword,sizeof(unpackedPassword));SecureZeroMemory(packed.data(),packed.size());
  t.samples.assign(SampleCount,basis(0));store.save(sid,t);check(store.enrolled(sid),"template persisted");check(match(basis(0),store.load(sid))>0.99,"encrypted template round-trip");
  check(!store.enrolled(L"S-1-5-21-1-2-3-1234"),"separate SID has no template");rejects([&]{store.load(L"..\\escape");},"path traversal rejected");
  auto faceFile=root/(sid+L".face");{std::fstream stream(faceFile,std::ios::binary|std::ios::in|std::ios::out);stream.seekg(-8,std::ios::end);char value=0;stream.read(&value,1);value^=0x55;stream.seekp(-8,std::ios::end);stream.write(&value,1);}
  rejects([&]{store.load(sid);},"tampered DPAPI template rejected");store.remove(sid);check(!store.enrolled(sid)&&!store.credential_saved(sid),"profile deletion also removes the saved Windows password");
  std::filesystem::remove(root/(sid+L".config"));std::filesystem::remove(root);
  std::stop_source cancel;auto begin=std::chrono::steady_clock::now();
  std::jthread canceller([&]{std::this_thread::sleep_for(std::chrono::milliseconds(150));cancel.request_stop();});
  rejects([&]{supervised_capture(CaptureKind::Preview,Config{},{},cancel.get_token(),{},{},true);},"unresponsive camera worker is cancelled without hanging parent");
  check(std::chrono::steady_clock::now()-begin<std::chrono::seconds(3),"capture cancellation is bounded");
}
class TestUser final:public ICredentialProviderUser {
  std::atomic<ULONG> refs{1};
public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=__uuidof(ICredentialProviderUser))return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE GetSid(wchar_t** sid)override{return SHStrDupW(current_sid().c_str(),sid);}
  HRESULT STDMETHODCALLTYPE GetProviderID(GUID* id)override{if(!id)return E_POINTER;*id=GUID_NULL;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetStringValue(REFPROPERTYKEY,wchar_t** text)override{if(text)*text=nullptr;return E_NOTIMPL;}
  HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY,PROPVARIANT* value)override{if(value)*value={};return E_NOTIMPL;}
};
class TestUsers final:public ICredentialProviderUserArray {
  std::atomic<ULONG> refs{1};
public:
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** p)override{if(!p)return E_POINTER;*p=nullptr;if(iid!=IID_IUnknown&&iid!=__uuidof(ICredentialProviderUserArray))return E_NOINTERFACE;*p=this;AddRef();return S_OK;}
  ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
  HRESULT STDMETHODCALLTYPE SetProviderFilter(REFGUID)override{return S_OK;}
  HRESULT STDMETHODCALLTYPE GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* o)override{if(!o)return E_POINTER;*o=CPAO_NONE;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetCount(DWORD* n)override{if(!n)return E_POINTER;*n=1;return S_OK;}
  HRESULT STDMETHODCALLTYPE GetAt(DWORD n,ICredentialProviderUser** user)override{if(!user)return E_POINTER;*user=nullptr;if(n)return E_INVALIDARG;*user=new TestUser;return S_OK;}
};
void provider_tests(const std::filesystem::path& dll) {
  CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);HMODULE module=LoadLibraryW(dll.c_str());check(module!=nullptr,"provider DLL loads without registration");
  auto get=reinterpret_cast<HRESULT(__stdcall*)(REFCLSID,REFIID,void**)>(GetProcAddress(module,"DllGetClassObject"));auto unload=reinterpret_cast<HRESULT(__stdcall*)()>(GetProcAddress(module,"DllCanUnloadNow"));check(get&&unload,"COM exports present");
  CLSID clsid{};CLSIDFromString(ProviderId,&clsid);IClassFactory* factory=nullptr;check(SUCCEEDED(get(clsid,IID_PPV_ARGS(&factory))),"class factory");
  ICredentialProvider* provider=nullptr;check(SUCCEEDED(factory->CreateInstance(nullptr,IID_PPV_ARGS(&provider))),"provider instantiated");
  check(provider->SetUsageScenario(CPUS_CREDUI,0)==E_NOTIMPL,"unsupported scenario rejected");check(SUCCEEDED(provider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION,0)),"unlock scenario accepted");
  ICredentialProviderSetUserArray* array=nullptr;check(SUCCEEDED(provider->QueryInterface(IID_PPV_ARGS(&array))),"V2 user array supported");auto users=new TestUsers;check(SUCCEEDED(array->SetUserArray(users)),"user association");users->Release();array->Release();
  DWORD count=0,selected=0;BOOL automatic=TRUE;check(SUCCEEDED(provider->GetCredentialCount(&count,&selected,&automatic))&&count==1&&!automatic&&selected==CREDENTIAL_PROVIDER_NO_DEFAULT,"does not request automatic Windows logon");
  DWORD fields=0;provider->GetFieldDescriptorCount(&fields);check(fields==5,"all provider fields");for(DWORD i=0;i<fields;++i){CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* desc=nullptr;check(SUCCEEDED(provider->GetFieldDescriptorAt(i,&desc)),"field descriptor");CoTaskMemFree(desc->pszLabel);CoTaskMemFree(desc);}
  ICredentialProviderCredential* credential=nullptr;check(SUCCEEDED(provider->GetCredentialAt(0,&credential)),"credential tile");ICredentialProviderCredential2* v2=nullptr;check(SUCCEEDED(credential->QueryInterface(IID_PPV_ARGS(&v2))),"V2 credential interface");wchar_t* sid=nullptr;v2->GetUserSid(&sid);check(sid&&current_sid()==sid,"tile bound to Windows SID");CoTaskMemFree(sid);v2->Release();
  CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialized{};wchar_t* text=nullptr;CREDENTIAL_PROVIDER_STATUS_ICON icon{};
  check(SUCCEEDED(credential->GetSerialization(&response,&serialized,&text,&icon)),"serialization call succeeds safely");check(response==CPGSR_NO_CREDENTIAL_NOT_FINISHED&&!serialized.rgbSerialization&&!serialized.cbSerialization,"no fabricated Windows credential");CoTaskMemFree(text);
  check(SUCCEEDED(provider->QueryInterface(IID_PPV_ARGS(&array))),"user array can be reattached for re-enumeration");users=new TestUsers;
  check(SUCCEEDED(array->SetUserArray(users)),"repeated Windows user enumeration succeeds");users->Release();array->Release();
  ICredentialProviderCredential* repeated=nullptr;check(SUCCEEDED(provider->GetCredentialAt(0,&repeated))&&repeated==credential,"unchanged user enumeration preserves the live credential object");if(repeated)repeated->Release();
  automatic=TRUE;check(SUCCEEDED(credential->SetSelected(&automatic))&&!automatic,"selection never triggers Windows authentication");credential->SetDeselected();credential->UnAdvise();credential->Release();provider->UnAdvise();provider->Release();factory->Release();check(unload()==S_OK,"COM objects released");FreeLibrary(module);CoUninitialize();
}
void model_tests(const std::filesystem::path& models) {
  Engine engine(models);std::wstring reason;
  check(!engine.observe(cv::Mat(480,640,CV_8UC3,cv::Scalar(100,100,100)),reason),"blank image yields no face");
  auto fixtures=models.parent_path()/L"tests"/L"fixtures";
  cv::Mat a=cv::imread(narrow((fixtures/L"lena.jpg").wstring()));check(!a.empty(),"positive fixture loaded");auto first=engine.observe(a,reason);check(first.has_value(),"YuNet landmarks and SFace embedding on fixture");
  cv::Mat changed;a.convertTo(changed,-1,0.85,15);auto second=engine.observe(changed,reason);check(second.has_value(),"lighting-varied fixture detected");
  check(cosine(first->embedding,second->embedding)>0.70f,"same face retained under light variation");
  cv::Mat unknown=cv::imread(narrow((fixtures/L"unknown.jpg").wstring()));check(!unknown.empty(),"unknown fixture loaded");cv::resize(unknown,unknown,{640,602});auto other=engine.observe(unknown,reason);if(!other)std::wcerr<<L"Unknown fixture observation: "<<reason<<L'\n';check(other.has_value(),"different face detected");
  auto similarity=cosine(first->embedding,other->embedding);std::cout<<"Different-face cosine: "<<similarity<<'\n';check(similarity<0.363f,"different fixture identity rejected");
  cv::Mat doubled;cv::hconcat(a,a,doubled);check(!engine.observe(doubled,reason),"multiple faces rejected");
  cv::Mat lowQuality=cv::imread(narrow((fixtures/L"messi5.jpg").wstring()));cv::resize(lowQuality,lowQuality,{},5,5,cv::INTER_CUBIC);check(!engine.observe(lowQuality,reason),"insufficient face quality is rejected");
}
void ipc_tests() {
  Request r;auto original=call(r,true);check(original.backendAvailable==0,"demo server never offers credential backend");
  check(original.ticket.version==0 && original.previewSize==0,"idle diagnostics receive no authorization or camera image");
  UnlockGrants forged;Request attempt;attempt.operation=Operation::ConsumeUnlock;attempt.ticket=forged.issue(current_sid(),1);wcscpy_s(attempt.targetSid,current_sid().c_str());
  rejects([&]{call(attempt,true);},"real listener refuses ordinary-client authorization consumption");
  attempt.operation=Operation::RetrieveWindowsCredential;
  rejects([&]{call(attempt,true);},"real listener refuses ordinary-client password retrieval even with a forged approval");
  check(original.windowsCredential.version==0&&original.passwordBackedBackend==0&&original.credentialSaved==0,"demo exposes neither saved passwords nor password-backed unlock");
  Config c=original.config;c.mode=Mode::Off;r.operation=Operation::Configure;r.config=c;call(r,true);
  r.operation=Operation::Status;auto off=call(r,true);check(off.phase==Phase::Disabled&&!off.cameraActive,"off keeps camera idle");
  r.operation=Operation::Recognize;rejects([&]{call(r,true);},"off rejects camera job");
  r.operation=Operation::Status;wcsncpy_s(r.targetSid,L"S-1-5-21-1-2-3-1234",_TRUNCATE);rejects([&]{call(r,true);},"cross-account pipe request rejected");r.targetSid[0]=0;
  r.operation=Operation::Configure;c.mode=Mode::Manual;c.cooldownSeconds=41;r.config=c;call(r,true);r.operation=Operation::Status;auto manual=call(r,true);check(manual.config.cooldownSeconds==41&&manual.config.mode==Mode::Manual,"IPC settings persist");
  r.operation=Operation::Configure;c.profile=Profile::Instant;r.config=c;call(r,true);r.operation=Operation::Status;
  check(call(r,true).config.profile==Profile::Instant,"live IPC saves and returns the Instant profile");
  r.operation=Operation::Configure;r.config.profile=static_cast<Profile>(4);rejects([&]{call(r,true);},"live IPC rejects unknown profiles");r.operation=Operation::Status;
  check(call(r,true).config.profile==Profile::Instant,"invalid profile cannot overwrite Instant settings");
  HANDLE rawToken=nullptr;if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&rawToken)){Handle token(rawToken);if(!fresh_interactive_token(token.get())){r.operation=Operation::Enroll;rejects([&]{call(r,true);},"listener denies enrollment without fresh OS verification");r.operation=Operation::Status;}}
  for(int i=0;i<20;++i)check(call(r,true).backendAvailable==0,"sequential pipe requests remain responsive");
  // Exercise real listener replay rejection, rather than just the validation helper.
  auto name=pipe_name(true);WaitNamedPipeW(name.c_str(),2000);
  Handle pipe(CreateFileW(name.c_str(),FILE_READ_DATA|FILE_WRITE_DATA,0,nullptr,OPEN_EXISTING,SECURITY_SQOS_PRESENT|SECURITY_IMPERSONATION,nullptr));check(static_cast<bool>(pipe),"raw test pipe opens");
  DWORD count=0;Hello hello;check(ReadFile(pipe.get(),&hello,sizeof(hello),&count,nullptr)&&count==sizeof(hello),"real nonce handshake");
  Request bad;bad.nonce=hello.nonce;bad.nonce[0]^=1;check(WriteFile(pipe.get(),&bad,sizeof(bad),&count,nullptr),"replayed message delivered");Response denied;check(ReadFile(pipe.get(),&denied,sizeof(denied),&count,nullptr)&&count==sizeof(denied)&&denied.error==ERROR_INVALID_DATA,"listener rejects bad nonce");DWORD ack=ProtocolMagic;WriteFile(pipe.get(),&ack,sizeof(ack),&count,nullptr);pipe.reset();
  r.operation=Operation::Configure;r.config=original.config;call(r,true);
}
}
int wmain(int argc,wchar_t** argv) {
  try{if(argc==3&&std::wstring(argv[1])==L"--provider")provider_tests(argv[2]);else if(argc==3&&std::wstring(argv[1])==L"--models")model_tests(argv[2]);else if(argc==2&&std::wstring(argv[1])==L"--ipc")ipc_tests();else core_tests();std::cout<<"PASS: "<<checks<<" checks\n";return 0;}catch(const std::exception& ex){std::cerr<<ex.what()<<" (after "<<checks<<" checks)\n";return 1;}
}
