#include "facepass/controller.hpp"
#include <iostream>
#include <condition_variable>
#include <deque>
#include <wtsapi32.h>
namespace {
SERVICE_STATUS_HANDLE statusHandle=nullptr;
SERVICE_STATUS status{};
std::stop_source stop;
std::mutex eventsMutex;
std::condition_variable eventsCv;
std::deque<std::pair<DWORD,DWORD>> events;
void report(DWORD state,DWORD error=0) {
  status.dwServiceType=SERVICE_WIN32_OWN_PROCESS; status.dwCurrentState=state; status.dwWin32ExitCode=error;
  status.dwControlsAccepted=state==SERVICE_RUNNING ? SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_SESSIONCHANGE|SERVICE_ACCEPT_POWEREVENT : 0;
  status.dwWaitHint=state==SERVICE_STOP_PENDING ? 30000 : 0;
  status.dwCheckPoint=state==SERVICE_STOP_PENDING ? 1 : 0;
  SetServiceStatus(statusHandle,&status);
}
DWORD WINAPI control(DWORD code,DWORD event,void* data,void*) {
  if(code==SERVICE_CONTROL_STOP||code==SERVICE_CONTROL_SHUTDOWN) { report(SERVICE_STOP_PENDING); stop.request_stop(); eventsCv.notify_all(); }
  else if(code==SERVICE_CONTROL_SESSIONCHANGE&&data) {
    auto notification=static_cast<WTSSESSION_NOTIFICATION*>(data);
    std::lock_guard lock(eventsMutex); if(events.size()<32) events.emplace_back(event,notification->dwSessionId); eventsCv.notify_one();
  } else if(code==SERVICE_CONTROL_POWEREVENT&&event==PBT_APMSUSPEND) {
    std::lock_guard lock(eventsMutex); events.emplace_back(WTS_CONSOLE_DISCONNECT,WTSGetActiveConsoleSessionId()); eventsCv.notify_one();
  }
  return NO_ERROR;
}
void WINAPI service_main(DWORD,wchar_t**) {
  statusHandle=RegisterServiceCtrlHandlerExW(facepass::ServiceName,control,nullptr); if(!statusHandle) return;
  report(SERVICE_START_PENDING);
  try {
    facepass::Controller controller(false,facepass::executable_dir()/L"models");
    facepass::PipeServer server(false,[&](const auto& c,const auto& r){return controller.handle(c,r);});
    std::exception_ptr serverFailure;
    std::jthread listener([&](std::stop_token){ try{server.run(stop.get_token());}catch(...){serverFailure=std::current_exception();stop.request_stop();eventsCv.notify_all();} });
    report(SERVICE_RUNNING); facepass::event_log(L"FacePass service started. Passwordless unlock requires an enabled, loaded custom authentication package.");
    while(!stop.stop_requested()) {
      std::unique_lock lock(eventsMutex);
      eventsCv.wait(lock,[&]{return stop.stop_requested()||!events.empty();});
      if(!events.empty()) { auto e=events.front(); events.pop_front(); lock.unlock(); controller.session_event(e.first,e.second); }
    }
    listener.join(); if(serverFailure) std::rethrow_exception(serverFailure);
    report(SERVICE_STOP_PENDING);
  } catch(const std::exception& ex) { facepass::event_log(L"Service failed safely: "+facepass::widen(ex.what()),EVENTLOG_ERROR_TYPE); report(SERVICE_STOPPED,ERROR_SERVICE_SPECIFIC_ERROR); return; }
  report(SERVICE_STOPPED);
}
BOOL WINAPI console_control(DWORD code) { if(code==CTRL_C_EVENT||code==CTRL_BREAK_EVENT||code==CTRL_CLOSE_EVENT){stop.request_stop();return TRUE;} return FALSE; }
}
int wmain(int argc,wchar_t** argv) {
  if(argc>1&&std::wstring(argv[1])==L"--console") {
    SetConsoleCtrlHandler(console_control,TRUE);
    try {
      facepass::Controller controller(true,facepass::executable_dir()/L"models");
      facepass::PipeServer server(true,[&](const auto& c,const auto& r){return controller.handle(c,r);});
      std::wcout<<L"FacePass per-user demo server. No service installation or Windows sign-in changes.\nPipe: "<<facepass::pipe_name(true)<<L"\nCtrl+C stops.\n";
      server.run(stop.get_token()); return 0;
    } catch(const std::exception& ex) { std::cerr<<ex.what()<<'\n';return 1; }
  }
  SERVICE_TABLE_ENTRYW table[]={{const_cast<wchar_t*>(facepass::ServiceName),service_main},{nullptr,nullptr}};
  if(!StartServiceCtrlDispatcherW(table)) { std::wcerr<<L"Start through SCM, or use --console for the per-user demo: "<<facepass::win_error()<<L'\n';return 1; }
  return 0;
}
