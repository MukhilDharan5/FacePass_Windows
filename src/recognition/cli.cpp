#include "facepass/ipc.hpp"
#include "facepass/vision.hpp"
#include "facepass/storage.hpp"
#include "facepass/capture.hpp"
#include <iostream>
#include <thread>
using namespace facepass;
int wmain(int argc,wchar_t** argv) {
  try {
    bool demo=false; std::wstring action=L"--status"; unsigned camera=0; bool watch=false,cameraSpecified=false;std::optional<Profile> profile;
    for(int i=1;i<argc;++i) {
      std::wstring arg=argv[i];
      if(arg==L"--demo") demo=true;
      else if(arg==L"--watch") watch=true;
      else if(arg==L"--camera"&&i+1<argc) { std::wstring value=argv[++i];size_t used=0;auto parsed=std::stoul(value,&used);if(used!=value.size()||parsed>15)throw std::runtime_error("Camera must be an integer from 0 to 15");camera=static_cast<unsigned>(parsed);cameraSpecified=true; }
      else if(arg==L"--profile") {
        if(i+1>=argc)throw std::runtime_error("--profile requires instant, convenience, balanced, or strict");
        std::wstring value=argv[++i];
        if(value==L"instant")profile=Profile::Instant;
        else if(value==L"convenience")profile=Profile::Convenience;
        else if(value==L"balanced")profile=Profile::Balanced;
        else if(value==L"strict")profile=Profile::Strict;
        else throw std::runtime_error("Profile must be instant, convenience, balanced, or strict");
      }
      else if(action!=L"--status" || arg==L"--camera") throw std::runtime_error("Specify one action; --camera requires an index");
      else action=arg;
    }
    if(action==L"--help") { std::wcout<<L"FacePassRecognition [--demo] --status|--manual|--automatic|--off|--enroll|--enroll-session|--scan|--cancel|--delete [--watch] [--camera 0..15]\n--profile instant|convenience|balanced|strict saves a profile with --status (default), --manual, --automatic, or --off.\nInstant accepts the first 2D face match without liveness checks; photos/video can unlock.\n--enroll-session uses a recent native sign-in token and never collects a password.\nStandalone: --preview, --local-enroll, --local-test, --camera-probe\n";return 0; }
    if(profile && action!=L"--status" && action!=L"--manual" && action!=L"--automatic" && action!=L"--off")throw std::runtime_error("--profile applies to --status, --manual, --automatic, or --off");
    if(action==L"--capture-probe") {
      std::stop_source stop;size_t pixels=0;Config config;config.mode=Mode::Manual;config.camera=camera;config.timeoutSeconds=5;
      try { supervised_capture(CaptureKind::Preview,config,{},stop.get_token(),{},[&](std::span<const BYTE> bytes){auto image=cv::imdecode(std::vector<BYTE>(bytes.begin(),bytes.end()),cv::IMREAD_COLOR);if(!image.empty()){pixels=image.total();stop.request_stop();}}); }
      catch(const std::exception&){if(!pixels)throw;}
      if(!pixels)throw std::runtime_error("Supervised camera probe returned no image");
      std::wcout<<L"PASS: supervised capture returned "<<pixels<<L" preview pixels in memory and stopped. No camera image saved.\n";return 0;
    }
    if(action==L"--preview"||action==L"--camera-probe") {
      Camera cap(camera); auto frame=cap.read();
      std::wcout<<L"Camera delivered "<<frame.cols<<L" x "<<frame.rows<<L" BGR pixels.\n";
      if(action==L"--camera-probe") return 0;
      std::wcout<<L"Escape closes camera preview.\n";
      while(true) { cv::imshow("FacePass camera preview - Escape closes",frame); if(cv::waitKey(30)==27) break; frame=cap.read(); } cv::destroyAllWindows(); return 0;
    }
    auto progress=[](const Outcome& o){std::wcout<<L"\r"<<o.progress<<L"% "<<o.message<<L"                    "<<std::flush;};
    if(action==L"--local-enroll"||action==L"--local-test") {
      Store store(data_dir(false)/L"standalone",false); auto sid=current_sid(); Config c=store.config(sid); c.mode=Mode::Manual; c.camera=camera;
      Handle auth; if(action==L"--local-enroll") auth=reauthenticate(nullptr);
      Engine engine(executable_dir()/L"models"); Camera cap(camera);
      if(action==L"--local-enroll") { auto t=enroll(cap,engine,c.profile,60,{},progress); store.save(sid,t); std::wcout<<L"\nEnrollment encrypted.\n"; }
      else { auto outcome=recognize(cap,engine,store.load(sid),c,{},progress); std::wcout<<L"\n"<<outcome.message<<L"\nCosine similarity: "<<outcome.similarity<<L'\n'; return outcome.phase==Phase::Recognized ? 0 : 2; }
      return 0;
    }
    Request request;
    if(action==L"--manual"||action==L"--automatic"||action==L"--off"||profile) {
      auto status=call(request,demo); request.operation=Operation::Configure; request.config=status.config;
      if(action!=L"--status")request.config.mode=action==L"--off"?Mode::Off:action==L"--automatic"?Mode::Automatic:Mode::Manual;
      if(profile)request.config.profile=*profile;
      if(cameraSpecified)request.config.camera=camera;
    } else if(action==L"--enroll"||action==L"--enroll-session") request.operation=Operation::Enroll;
    else if(action==L"--scan") request.operation=Operation::Recognize;
    else if(action==L"--cancel") request.operation=Operation::Cancel;
    else if(action==L"--delete") request.operation=Operation::DeleteProfile;
    else if(action!=L"--status") throw std::runtime_error("Unknown command; use --help");
    Handle auth; if(request.operation==Operation::Enroll) auth=action==L"--enroll-session"?recent_session_authentication():reauthenticate(nullptr);
    auto response=call(request,demo,auth ? auth.get() : nullptr);
    auto profileName=response.config.profile==Profile::Instant?L"Instant":response.config.profile==Profile::Strict?L"Strict":response.config.profile==Profile::Balanced?L"Balanced":L"Convenience";
    std::wcout<<response.message<<L"\nEnrolled: "<<response.enrolled<<L"  Camera active: "<<response.cameraActive<<L"  Mode: "<<static_cast<unsigned>(response.config.mode)<<L"  Profile: "<<profileName<<L"  Unlock backend: "<<(response.backendAvailable?L"enabled":L"not enabled/loaded")<<L"  Saved Windows password: "<<response.credentialSaved<<L"\n";
    while(watch&&response.cameraActive) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500)); request.operation=Operation::Status;
      response=call(request,demo); std::wcout<<L"\r"<<response.progress<<L"% "<<response.message<<L"                  "<<std::flush;
    }
    if(watch) std::wcout<<L'\n';
    if(watch && (action==L"--scan"||action==L"--enroll"||action==L"--enroll-session")) {
      if(response.phase==Phase::Cancelled)return 3;
      return response.phase==Phase::Recognized||response.phase==Phase::Enrolled?0:2;
    }
    return 0;
  } catch(const std::exception& ex) { std::cerr<<ex.what()<<'\n';return 1; }
}
