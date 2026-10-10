#include "facepass/ipc.hpp"
#include <sddl.h>
#include <cstring>
#include <algorithm>
#include <winsvc.h>
namespace facepass {
namespace {
bool transfer(HANDLE pipe, void* buffer, DWORD size, bool write, unsigned timeout, std::stop_token stop={}) {
  Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr)); if(!event) fail("IPC event");
  OVERLAPPED ov{}; ov.hEvent=event.get(); DWORD done=0;
  BOOL ok=write ? WriteFile(pipe,buffer,size,&done,&ov) : ReadFile(pipe,buffer,size,&done,&ov);
  if(!ok && GetLastError()!=ERROR_IO_PENDING) return false;
  if(!ok) {
    auto deadline=GetTickCount64()+timeout;
    while(!stop.stop_requested() && GetTickCount64()<deadline) {
      if(WaitForSingleObject(event.get(),50)==WAIT_OBJECT_0) { ok=GetOverlappedResult(pipe,&ov,&done,FALSE); break; }
    }
    if(!ok) { CancelIoEx(pipe,&ov); GetOverlappedResult(pipe,&ov,&done,TRUE); return false; }
  }
  return done==size;
}
void verify_server(HANDLE pipe,bool demo) {
  ULONG pid=0; if(!GetNamedPipeServerProcessId(pipe,&pid)) fail("Query pipe server");
  if(!demo) {
    SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(!manager) fail("SCM verification");
    SC_HANDLE service=OpenServiceW(manager,ServiceName,SERVICE_QUERY_STATUS);
    if(!service) { auto error=GetLastError(); CloseServiceHandle(manager); fail("FacePass service",error); }
    SERVICE_STATUS_PROCESS info{}; DWORD bytes=0;
    BOOL ok=QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&info),sizeof(info),&bytes);
    CloseServiceHandle(service); CloseServiceHandle(manager);
    if(!ok||info.dwCurrentState!=SERVICE_RUNNING||info.dwProcessId!=pid) throw std::runtime_error("Named pipe is not owned by the running FacePass Windows service");
  } else {
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid)); if(!process) fail("Verify demo process");
    HANDLE raw=nullptr; if(!OpenProcessToken(process.get(),TOKEN_QUERY,&raw)) fail("Demo owner"); Handle token(raw);
    if(token_sid(token.get())!=current_sid()) throw std::runtime_error("Demo server belongs to another user");
    wchar_t image[32768]{}; DWORD length=32768;
    if(!QueryFullProcessImageNameW(process.get(),0,image,&length)) fail("Demo server image");
    auto expected=executable_dir()/L"FaceUnlockService.exe";
    if(_wcsicmp(std::filesystem::weakly_canonical(image).c_str(),std::filesystem::weakly_canonical(expected).c_str())!=0) throw std::runtime_error("Unexpected demo server executable");
  }
}
Caller caller_for(HANDLE pipe) {
  if(!ImpersonateNamedPipeClient(pipe)) fail("Authenticate pipe client");
  struct Revert { ~Revert(){RevertToSelf();} } guard;
  HANDLE raw=nullptr; if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) fail("Client token");
  Handle token(raw); Caller c; c.sid=token_sid(token.get()); c.system=is_system_sid(c.sid); c.fresh=fresh_interactive_token(token.get());
  ULONG pid=0;
  if(GetNamedPipeClientProcessId(pipe,&pid)) {
    ProcessIdToSessionId(pid,&c.session);
    if(c.system) {
      Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));
      wchar_t image[32768]{},system[32768]{}; DWORD length=std::size(image);
      if(process && QueryFullProcessImageNameW(process.get(),0,image,&length) && GetSystemDirectoryW(system,std::size(system))) {
        auto base=std::filesystem::path(system);
        if(_wcsicmp(image,(base/L"LogonUI.exe").c_str())==0) c.role=ClientRole::Provider;
        else if(c.session==0 && _wcsicmp(image,(base/L"lsass.exe").c_str())==0) c.role=ClientRole::Authority;
      }
    }
  }
  return c;
}
}
bool valid_request(const Hello& h,const Request& r,std::uint64_t now) {
  bool consume=r.operation==Operation::ConsumeUnlock||r.operation==Operation::RetrieveWindowsCredential;
  return h.magic==ProtocolMagic && h.version==ProtocolVersion && r.magic==ProtocolMagic && r.version==ProtocolVersion
    && r.nonce==h.nonce && now<=h.expires && static_cast<unsigned>(r.operation)<=static_cast<unsigned>(Operation::RetrieveWindowsCredential)
    && std::find(std::begin(r.targetSid),std::end(r.targetSid),L'\0')!=std::end(r.targetSid)
    && (r.operation!=Operation::Configure||valid_config(r.config))
    && (consume ? valid_ticket(r.ticket,now) && std::wstring(r.targetSid)==r.ticket.sid : r.ticket.version==0)
    && (r.operation==Operation::SaveWindowsCredential ? valid_windows_credential(r.windowsCredential) : r.windowsCredential.version==0);
}
bool authorize(const Caller& c,Operation op,const std::wstring& target) {
  if(c.sid.empty()) return false;
  if(c.system) {
    if(c.role==ClientRole::Authority) return !target.empty() && op==Operation::ConsumeUnlock;
    return c.role==ClientRole::Provider && !target.empty() && (op==Operation::Status||op==Operation::Recognize||op==Operation::Cancel||op==Operation::RetrieveWindowsCredential||op==Operation::DeleteWindowsCredential);
  }
  if(op==Operation::ConsumeUnlock || op==Operation::RetrieveWindowsCredential || c.role!=ClientRole::User) return false;
  if(!target.empty()&&target!=c.sid) return false;
  return (op!=Operation::Enroll&&op!=Operation::SaveWindowsCredential)||c.fresh;
}
void set_message(Response& r,const std::wstring& message) { wcsncpy_s(r.message,message.c_str(),_TRUNCATE); }
Response call(const Request& request,bool demo,HANDLE enrollmentToken) {
  auto name=pipe_name(demo);
  Handle pipe;
  {
    Impersonation authenticated(enrollmentToken);
    pipe.reset(CreateFileW(name.c_str(),FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IMPERSONATION,nullptr));
    if(!pipe&&GetLastError()==ERROR_PIPE_BUSY) {
      if(!WaitNamedPipeW(name.c_str(),2000)) fail("Wait for FacePass pipe");
      pipe.reset(CreateFileW(name.c_str(),FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IMPERSONATION,nullptr));
    }
  }
  if(!pipe) fail("Connect to FacePass service");
  verify_server(pipe.get(),demo);
  DWORD mode=PIPE_READMODE_MESSAGE;
  if(!SetNamedPipeHandleState(pipe.get(),&mode,nullptr,nullptr)) fail("Set pipe mode");
  Hello hello{};
  if(!transfer(pipe.get(),&hello,sizeof(hello),false,2500)) throw std::runtime_error("Service handshake timed out");
  Request r=request; r.nonce=hello.nonce;
  if(!valid_request(hello,r,unix_millis())) throw std::runtime_error("Invalid or expired service handshake");
  // Keep the authenticated impersonation context through the write as well as pipe creation.
  { Impersonation authenticated(enrollmentToken); if(!transfer(pipe.get(),&r,sizeof(r),true,2000)) throw std::runtime_error("Service request failed"); }
  Response response{};
  if(!transfer(pipe.get(),&response,sizeof(response),false,2500)) throw std::runtime_error("Service response timed out");
  // Bounded acknowledgement lets the server disconnect without dropping a buffered response.
  DWORD ack=ProtocolMagic; transfer(pipe.get(),&ack,sizeof(ack),true,500);
  if(response.magic!=ProtocolMagic||response.version!=ProtocolVersion||response.nonce!=hello.nonce
    ||response.backendAvailable>1||response.passwordBackedBackend>1||response.credentialSaved>1||!valid_config(response.config)||response.enrolled>1||response.cameraActive>1||response.progress>100||static_cast<unsigned>(response.phase)>static_cast<unsigned>(Phase::Cancelled)
    ||(response.ticket.version!=0 && !valid_ticket(response.ticket,unix_millis()))
    ||response.previewSize>PreviewCapacity
    ||std::find(std::begin(response.message),std::end(response.message),L'\0')==std::end(response.message)
    ||(response.windowsCredential.version!=0 && (demo||request.operation!=Operation::RetrieveWindowsCredential
       ||!valid_windows_credential(response.windowsCredential)||std::wstring(response.windowsCredential.sid)!=request.targetSid))) throw std::runtime_error("Invalid service response");
  if(response.error) throw std::runtime_error("FacePass: "+narrow((response.message[0]?std::wstring(response.message)+L". ":std::wstring{})+win_error(response.error))); return response;
}
PipeServer::PipeServer(bool demo,RequestHandler handler):demo_(demo),handler_(std::move(handler)) {
  std::wstring sid=current_sid();
  auto sddl=L"D:P(A;;GA;;;SY)(A;;GA;;;"+sid+L")(A;;0x12019b;;;"+(demo ? sid : std::wstring(L"IU"))+L")";
  PSECURITY_DESCRIPTOR desc=nullptr;
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&desc,nullptr)) fail("Pipe ACL");
  SECURITY_ATTRIBUTES attr{sizeof(attr),desc,FALSE};
  pipe_.reset(CreateNamedPipeW(pipe_name(demo).c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,sizeof(Response),sizeof(Request),0,&attr));
  auto error=GetLastError(); LocalFree(desc); if(!pipe_) fail("Create private pipe (an instance may already exist)",error);
}
void PipeServer::run(std::stop_token stop) {
  Handle cancellation(CreateEventW(nullptr,TRUE,FALSE,nullptr));if(!cancellation)fail("IPC stop event");
  std::stop_callback onStop(stop,[&]{SetEvent(cancellation.get());});
  while(!stop.stop_requested()) {
    Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr)); if(!event) fail("Pipe connect event");
    OVERLAPPED ov{}; ov.hEvent=event.get();
    BOOL connected=ConnectNamedPipe(pipe_.get(),&ov);
    DWORD error=connected ? ERROR_SUCCESS : GetLastError();
    if(error==ERROR_IO_PENDING) {
      HANDLE waits[]={event.get(),cancellation.get()};
      WaitForMultipleObjects(2,waits,FALSE,INFINITE);
      DWORD done=0;
      if(stop.stop_requested()) { CancelIoEx(pipe_.get(),&ov); GetOverlappedResult(pipe_.get(),&ov,&done,TRUE); break; }
      connected=GetOverlappedResult(pipe_.get(),&ov,&done,FALSE);
    } else if(error==ERROR_PIPE_CONNECTED) connected=TRUE;
    if(!connected) { DisconnectNamedPipe(pipe_.get()); continue; }
    try {
      Hello hello; random_bytes(hello.nonce); hello.expires=unix_millis()+3000;
      Request r{};
      if(transfer(pipe_.get(),&hello,sizeof(hello),true,1000,stop)&&transfer(pipe_.get(),&r,sizeof(r),false,2000,stop)) {
        Response response{}; response.nonce=hello.nonce;
        if(!valid_request(hello,r,unix_millis())) { response.error=ERROR_INVALID_DATA; set_message(response,L"Invalid, replayed, or expired request"); }
        else {
          auto c=caller_for(pipe_.get());
          if(!authorize(c,r.operation,r.targetSid)) { response.error=ERROR_ACCESS_DENIED; set_message(response,L"Windows account verification is required for enrollment"); }
          else { response=handler_(c,r); response.nonce=hello.nonce; }
        }
        if(transfer(pipe_.get(),&response,sizeof(response),true,1000,stop)) {
          DWORD ack=0;transfer(pipe_.get(),&ack,sizeof(ack),false,500,stop);
        }
      }
    } catch(const std::exception& ex) { event_log(L"IPC rejected: "+widen(ex.what()),EVENTLOG_WARNING_TYPE); }
    // No FlushFileBuffers: a malicious/non-reading client must never block the listener.
    DisconnectNamedPipe(pipe_.get());
  }
}
}
