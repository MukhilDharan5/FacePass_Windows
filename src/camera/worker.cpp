#include "facepass/capture.hpp"
#include <iostream>
#include <thread>
using namespace facepass;
int wmain(int argc,wchar_t** argv) {
  if((argc!=6 && argc!=7)||std::wstring(argv[1])!=L"--capture")return 1;
  CaptureShared* shared=nullptr;
  try {
    auto parse=[](const wchar_t* value){size_t used=0;auto number=std::stoull(value,&used);if(used!=wcslen(value)||number==0)throw std::runtime_error("Invalid inherited capture handle");return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(number));};
    Handle mapping(parse(argv[2])),mutex(parse(argv[3])),event(parse(argv[4])),cancel(parse(argv[5]));
    shared=static_cast<CaptureShared*>(MapViewOfFile(mapping.get(),FILE_MAP_ALL_ACCESS,0,0,sizeof(CaptureShared)));
    if(!shared)return 1;
    struct Unmap {CaptureShared* p;~Unmap(){UnmapViewOfFile(p);}} unmap{shared};
    if(shared->magic!=ProtocolMagic || !valid_config(shared->config) || shared->inputCount>SampleCount || static_cast<unsigned>(shared->kind)>2)return 1;
    if(argc==7) { if(std::wstring(argv[6])!=L"--probe-hang")return 1; Sleep(INFINITE);return 1; }
    auto update=[&](const Outcome& outcome,bool done=false,const Template* enrolled=nullptr) {
      if(WaitForSingleObject(mutex.get(),250)!=WAIT_OBJECT_0)throw std::runtime_error("Capture parent channel unavailable");
      shared->phase=outcome.phase;shared->similarity=outcome.similarity;shared->progress=outcome.progress;
      wcsncpy_s(shared->message,outcome.message.c_str(),_TRUNCATE);shared->done=done;
      if(enrolled){shared->outputCount=static_cast<unsigned>(enrolled->samples.size());std::copy(enrolled->samples.begin(),enrolled->samples.end(),shared->output.begin());}
      ReleaseMutex(mutex.get());SetEvent(event.get());
    };
    std::stop_source stop;
    std::jthread monitor([&](std::stop_token ending){while(!ending.stop_requested())if(WaitForSingleObject(cancel.get(),50)==WAIT_OBJECT_0){stop.request_stop();break;}});
    auto preview=[&](const cv::Mat& frame) {
      if(!shared->previewAllowed)return;
      cv::Mat small;cv::resize(frame,small,{320,240});std::vector<BYTE> jpeg;
      cv::imencode(".jpg",small,jpeg,{cv::IMWRITE_JPEG_QUALITY,60});
      if(jpeg.size()>PreviewCapacity)return;
      if(WaitForSingleObject(mutex.get(),250)!=WAIT_OBJECT_0)throw std::runtime_error("Preview channel unavailable");
      shared->previewSize=static_cast<unsigned>(jpeg.size());std::copy(jpeg.begin(),jpeg.end(),shared->preview.begin());
      ReleaseMutex(mutex.get());SetEvent(event.get());
    };
    try {
      Camera camera(shared->config.camera);
      if(shared->kind==CaptureKind::Preview) {
        update({Phase::Capturing,0,0,L"Camera preview is active. Close the preview to release the camera."});
        while(!stop.stop_requested()){preview(camera.read());std::this_thread::sleep_for(std::chrono::milliseconds(100));}
        update({Phase::Cancelled,0,0,L"Preview closed. Camera released."},true);
      } else {
        Engine engine(executable_dir()/L"models");
        if(shared->kind==CaptureKind::Enroll) {
          auto result=enroll(camera,engine,shared->config.profile,std::max(45u,shared->config.timeoutSeconds),stop.get_token(),[&](const Outcome& o){update(o);},preview);
          update({Phase::Enrolled,0,100,L"Seven quality samples captured."},true,&result);
          for(auto& sample:result.samples)SecureZeroMemory(sample.data(),sizeof(sample));
        } else {
          Template enrolled;enrolled.samples.assign(shared->input.begin(),shared->input.begin()+shared->inputCount);
          auto outcome=recognize(camera,engine,enrolled,shared->config,stop.get_token(),[&](const Outcome& o){update(o);},preview);
          for(auto& sample:enrolled.samples)SecureZeroMemory(sample.data(),sizeof(sample));
          update(outcome,true);
        }
      }
    }catch(const std::exception& ex){update({stop.stop_requested()?Phase::Cancelled:Phase::Error,0,0,widen(ex.what())},true);}
    monitor.request_stop();return 0;
  }catch(...){return 1;}
}
