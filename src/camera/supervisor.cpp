#include "facepass/capture.hpp"
#include <cstring>
#include <cmath>

namespace facepass {
namespace {
struct Mapping { CaptureShared* data=nullptr; ~Mapping(){if(data){SecureZeroMemory(data,sizeof(*data));UnmapViewOfFile(data);}} };
struct Attributes { std::vector<BYTE> bytes; LPPROC_THREAD_ATTRIBUTE_LIST list=nullptr; ~Attributes(){if(list)DeleteProcThreadAttributeList(list);} };
}
CaptureResult supervised_capture(CaptureKind kind,const Config& config,const Template& enrolled,std::stop_token stop,const Progress& progress,const PreviewSink& preview,bool testHang) {
  if(!valid_config(config) || static_cast<unsigned>(kind)>2 || (kind==CaptureKind::Recognize && enrolled.samples.size()!=SampleCount)) throw std::runtime_error("Invalid capture request");
  SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};
  Handle mapping(CreateFileMappingW(INVALID_HANDLE_VALUE,&security,PAGE_READWRITE,0,sizeof(CaptureShared),nullptr));
  Handle mutex(CreateMutexW(&security,FALSE,nullptr)),event(CreateEventW(&security,FALSE,FALSE,nullptr)),cancel(CreateEventW(&security,TRUE,FALSE,nullptr));
  if(!mapping || !mutex || !event || !cancel) fail("Create private capture channel");
  Mapping view{static_cast<CaptureShared*>(MapViewOfFile(mapping.get(),FILE_MAP_ALL_ACCESS,0,0,sizeof(CaptureShared)))};
  if(!view.data) fail("Map capture channel");
  *view.data=CaptureShared{};view.data->kind=kind;view.data->config=config;
  view.data->previewAllowed=preview?1:0;
  view.data->inputCount=static_cast<unsigned>(enrolled.samples.size());
  if(enrolled.samples.size()>SampleCount) throw std::runtime_error("Invalid enrollment sample count");
  std::copy(enrolled.samples.begin(),enrolled.samples.end(),view.data->input.begin());
  Handle job(CreateJobObjectW(nullptr,nullptr));if(!job)fail("Create capture job");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limits.BasicLimitInformation.ActiveProcessLimit=1;
  if(!SetInformationJobObject(job.get(),JobObjectExtendedLimitInformation,&limits,sizeof(limits)))fail("Limit capture job");
  Attributes attributes;SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&bytes);attributes.bytes.resize(bytes);
  auto list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.bytes.data());
  if(!InitializeProcThreadAttributeList(list,1,0,&bytes))fail("Capture handle list");attributes.list=list;
  HANDLE inherited[]={mapping.get(),mutex.get(),event.get(),cancel.get()};
  if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr))fail("Restrict inherited capture handles");
  auto executable=executable_dir()/L"FacePassCapture.exe";
  std::wstring command=L"\""+executable.wstring()+L"\" --capture";
  for(auto handle:inherited)command+=L" "+std::to_wstring(reinterpret_cast<uintptr_t>(handle));
  if(testHang)command+=L" --probe-hang";
  STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);startup.lpAttributeList=list;PROCESS_INFORMATION process{};
  if(!CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,executable_dir().c_str(),&startup.StartupInfo,&process))fail("Launch capture worker");
  Handle child(process.hProcess),thread(process.hThread);
  if(!AssignProcessToJobObject(job.get(),child.get())) { auto error=GetLastError();TerminateProcess(child.get(),1);fail("Assign capture worker job",error); }
  if(ResumeThread(thread.get())==static_cast<DWORD>(-1))fail("Start capture worker");
  auto started=std::chrono::steady_clock::now();
  const auto duration=std::chrono::seconds((kind==CaptureKind::Enroll?std::max(45u,config.timeoutSeconds):config.timeoutSeconds)+5);
  while(true) {
    if(stop.stop_requested() || std::chrono::steady_clock::now()-started>=duration) {
      SetEvent(cancel.get()); if(WaitForSingleObject(child.get(),250)!=WAIT_OBJECT_0)TerminateJobObject(job.get(),ERROR_TIMEOUT);
      WaitForSingleObject(child.get(),1000);
      throw std::runtime_error(stop.stop_requested()?"Capture cancelled; worker stopped and camera released.":"Capture exceeded its deadline; blocked camera worker was terminated.");
    }
    HANDLE waits[]={event.get(),child.get()};auto wait=WaitForMultipleObjects(2,waits,FALSE,50);
    if(wait==WAIT_TIMEOUT)continue;
    if(wait==WAIT_FAILED)fail("Wait for capture result");
    auto locked=WaitForSingleObject(mutex.get(),250);
    if(locked==WAIT_ABANDONED){ReleaseMutex(mutex.get());throw std::runtime_error("Capture worker lost its channel lock");}
    if(locked!=WAIT_OBJECT_0)throw std::runtime_error("Capture worker channel timed out");
    CaptureShared snapshot=*view.data;ReleaseMutex(mutex.get());
    if(snapshot.magic!=ProtocolMagic || snapshot.progress>100 || snapshot.previewSize>PreviewCapacity || snapshot.outputCount>SampleCount
        || !std::isfinite(snapshot.similarity) || std::find(std::begin(snapshot.message),std::end(snapshot.message),L'\0')==std::end(snapshot.message)
        || static_cast<unsigned>(snapshot.phase)>static_cast<unsigned>(Phase::Cancelled)) throw std::runtime_error("Invalid capture worker response");
    Outcome outcome{snapshot.phase,snapshot.similarity,snapshot.progress,snapshot.message};
    if(progress)progress(outcome);
    if(preview && snapshot.previewSize)preview({snapshot.preview.data(),snapshot.previewSize});
    if(snapshot.done) {
      if(WaitForSingleObject(child.get(),1000)!=WAIT_OBJECT_0){TerminateJobObject(job.get(),ERROR_TIMEOUT);throw std::runtime_error("Capture worker failed to release camera after completion");}
      DWORD exit=1;if(!GetExitCodeProcess(child.get(),&exit)||exit!=0)throw std::runtime_error("Capture worker failed after inference");
      CaptureResult result;result.outcome=std::move(outcome);
      result.enrolled.samples.assign(snapshot.output.begin(),snapshot.output.begin()+snapshot.outputCount);
      SecureZeroMemory(snapshot.input.data(),sizeof(snapshot.input));SecureZeroMemory(snapshot.output.data(),sizeof(snapshot.output));
      if(kind==CaptureKind::Enroll && result.outcome.phase==Phase::Enrolled && result.enrolled.samples.size()!=SampleCount)throw std::runtime_error("Incomplete enrollment result");
      return result;
    }
    if(wait==WAIT_OBJECT_0+1)throw std::runtime_error("Capture worker exited before returning a result");
  }
}
}
