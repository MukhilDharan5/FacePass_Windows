#include "facepass/vision.hpp"
#include <iostream>

namespace {
int checks=0;
void check(bool condition,const char* label) {
  ++checks;if(!condition)throw std::runtime_error(std::string("Camera fallback FAILED: ")+label);
}
enum class Frame { Bgr,Bgra,Empty,FalseWithImage,Gray,Float,Large,DriverError };
struct Attempt {
  unsigned index;int api;bool opens;
  std::vector<Frame> frames;
  bool driverError=false;
};
struct State {
  std::vector<std::vector<facepass::detail::CameraDevice>> inventories;
  std::vector<Attempt> script;
  size_t enumerations=0,opens=0,reads=0;
  std::optional<size_t> active;
};
class Backend final : public facepass::detail::CameraBackend {
  std::shared_ptr<State> state_;
public:
  explicit Backend(std::shared_ptr<State> state):state_(std::move(state)){}
  std::vector<facepass::detail::CameraDevice> devices() override {
    auto n=state_->enumerations++;
    return state_->inventories[std::min(n,state_->inventories.size()-1)];
  }
  bool open(unsigned index,int api) override {
    check(!state_->active,"previous capture is released before another open");
    check(state_->opens<state_->script.size(),"no unplanned retries or unrelated camera opens");
    auto n=state_->opens++;auto& attempt=state_->script[n];
    check(index==attempt.index&&api==attempt.api,"opens the intended device on the intended backend");
    if(attempt.driverError)CV_Error(cv::Error::StsError,"Synthetic camera driver open error");
    if(attempt.opens){state_->active=n;state_->reads=0;}
    return attempt.opens;
  }
  bool read(cv::Mat& frame) override {
    check(state_->active.has_value(),"reads only an open capture");
    auto& frames=state_->script[*state_->active].frames;
    auto n=state_->reads++;
    auto value=n<frames.size()?frames[n]:Frame::Empty;
    switch(value) {
    case Frame::Bgr:frame=cv::Mat(480,640,CV_8UC3,cv::Scalar(20,30,40));return true;
    case Frame::Bgra:frame=cv::Mat(480,640,CV_8UC4,cv::Scalar(20,30,40,255));return true;
    case Frame::FalseWithImage:frame=cv::Mat(480,640,CV_8UC3);return false;
    case Frame::Gray:frame=cv::Mat(480,640,CV_8UC1);return true;
    case Frame::Float:frame=cv::Mat(480,640,CV_32FC3);return true;
    case Frame::Large:frame=cv::Mat(1200,2000,CV_8UC3,cv::Scalar(20,30,40));return true;
    case Frame::DriverError:CV_Error(cv::Error::StsError,"Synthetic camera driver read error");
    default:return false;
    }
  }
  void release() override {state_->active.reset();}
};
using facepass::detail::CameraDevice;
const CameraDevice physical{0,L"Integrated camera",L"physical-link",false,7};
const CameraDevice phone{1,L"My handset Windows Virtual Camera",L"phone-link",true,4};
std::shared_ptr<State> state(std::vector<Attempt> script,std::vector<CameraDevice> devices={physical,phone}) {
  auto result=std::make_shared<State>();result->script=std::move(script);result->inventories.push_back(std::move(devices));return result;
}
facepass::Camera camera(const std::shared_ptr<State>& state,unsigned index=0) {
  return facepass::Camera(index,std::make_unique<Backend>(state));
}
template<class F>void unavailable(F action) {
  std::string message;
  try{action();}catch(const std::runtime_error& error){message=error.what();}
  check(message.find("selected camera source is unavailable")!=std::string::npos,"exhaustion reports that the selected camera source is unavailable");
}
}
int camera_fallback_tests() {
  checks=0;
  using facepass::detail::is_windows_virtual_camera;
  check(is_windows_virtual_camera(L"My custom handset Windows Virtual Camera",false),"recognizes a custom phone name by the Windows suffix");
  check(is_windows_virtual_camera(L"handset WINDOWS VIRTUAL CAMERA",false),"native camera suffix is case insensitive");
  check(is_windows_virtual_camera(L"handset (Windows Virtual Camera) ",false),"recognizes a parenthesized Windows virtual camera suffix");
  check(is_windows_virtual_camera(L"Localized native camera",true),"device-interface metadata works without an English name");
  check(!is_windows_virtual_camera(L"OBS Virtual Camera",false),"does not mistake a third-party virtual camera for a native Windows camera");
  check(!is_windows_virtual_camera(L"Phone webcam",false),"does not guess based on phone-like names");
  check(!is_windows_virtual_camera(L"Integrated camera",false),"physical cameras are not automatic virtual-camera candidates");
  {
    auto s=state({{0,cv::CAP_MSMF,true,{Frame::Bgr,Frame::Bgr}}});auto cap=camera(s);
    check(cap.read().type()==CV_8UC3&&cap.read().cols==640,"healthy selected camera keeps delivering frames");
    check(s->opens==1&&s->enumerations==1&&cap.generation()==1,"healthy primary never activates a phone camera");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,false,{}},{7,cv::CAP_DSHOW,true,{Frame::Bgr}}});auto cap=camera(s);
    check(!cap.read().empty()&&cap.name()==physical.name,"DirectShow preserves the selected physical camera");
    check(s->opens==2&&s->enumerations==1,"DirectShow uses its mapped device index before phone failover");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,false,{}},{7,cv::CAP_DSHOW,false,{}},{1,cv::CAP_MSMF,true,{Frame::Bgra}}});auto cap=camera(s);
    auto frame=cap.read();
    check(frame.type()==CV_8UC3&&frame.at<cv::Vec3b>(0,0)==cv::Vec3b(20,30,40),"phone BGRA converts to recognition's BGR format");
    check(cap.name()==phone.name&&s->opens==3&&s->enumerations==2,"unavailable primary activates the native phone camera");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,true,{Frame::Empty}},{7,cv::CAP_DSHOW,true,{Frame::Empty}},{1,cv::CAP_MSMF,true,{Frame::Bgr}}});auto cap=camera(s);
    check(!cap.read().empty()&&cap.name()==phone.name,"an open camera with no first frame still falls back to the phone");
    check(cap.generation()==3,"every replacement stream changes the generation for recognition reset");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,true,{Frame::Bgr,Frame::Empty}},{7,cv::CAP_DSHOW,false,{}},{1,cv::CAP_MSMF,true,{Frame::Bgr}}},{physical});
    s->inventories.push_back({phone});auto cap=camera(s);cap.read();auto generation=cap.generation();cap.read();
    check(cap.name()==phone.name&&cap.generation()>generation,"a disconnection after delivery discovers a newly available phone");
  }
  for(auto failure:{Frame::FalseWithImage,Frame::Gray,Frame::Float,Frame::DriverError}) {
    auto selected=physical;selected.directShowIndex.reset();
    auto s=state({{0,cv::CAP_MSMF,true,{failure}},{1,cv::CAP_MSMF,true,{Frame::Bgr}}},{selected,phone});auto cap=camera(s);
    check(cap.read().type()==CV_8UC3&&cap.name()==phone.name,"failed, invalid and exception frames cannot hide camera failure");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,false,{},true},{7,cv::CAP_DSHOW,false,{},true},{1,cv::CAP_MSMF,true,{Frame::Large}}});auto cap=camera(s);
    check(cap.read().size()==cv::Size(640,480),"open-driver exceptions fail over and oversized phone frames are resized");
  }
  {
    auto s=state({{15,cv::CAP_MSMF,false,{}},{1,cv::CAP_MSMF,true,{Frame::Bgr}}},{phone});auto cap=camera(s,15);
    check(!cap.read().empty()&&cap.name()==phone.name,"a missing saved primary camera still uses the phone");
  }
  {
    auto other=phone;other.index=2;other.symbolicLink=L"other-phone";other.name=L"Second phone Windows Virtual Camera";
    auto s=state({{1,cv::CAP_MSMF,false,{}},{2,cv::CAP_MSMF,true,{Frame::Bgr}}},{phone,other});auto cap=camera(s,1);
    check(!cap.read().empty()&&cap.name()==other.name,"a selected virtual camera skips DirectShow and duplicate attempts");
  }
  {
    auto other=phone;other.index=3;other.symbolicLink=L"other-phone";
    auto s=state({{0,cv::CAP_MSMF,false,{}},{7,cv::CAP_DSHOW,false,{}},{1,cv::CAP_MSMF,true,{Frame::Empty}},{3,cv::CAP_MSMF,true,{Frame::Bgr}}},{physical,phone,other});auto cap=camera(s);
    check(!cap.read().empty()&&s->opens==4,"a disconnected first phone does not prevent using the next native virtual camera");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,false,{}},{7,cv::CAP_DSHOW,false,{}}},{physical,{2,L"OBS Virtual Camera",L"obs",false,2},{3,L"USB camera",L"usb",false,3}});
    unavailable([&]{auto cap=camera(s);});check(s->opens==2,"unrelated cameras are not automatic fallback candidates");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,false,{}},{0,cv::CAP_DSHOW,false,{}}},{});unavailable([&]{auto cap=camera(s);});
    check(s->opens==2&&s->enumerations==2,"no cameras fails after finite attempts on both selected backends");
  }
  {
    auto s=state({{0,cv::CAP_MSMF,false,{}},{0,cv::CAP_DSHOW,true,{Frame::Bgr}}},{});auto cap=camera(s);
    check(!cap.read().empty()&&s->opens==2,"DirectShow-only cameras remain usable when MF enumerates no devices");
  }
  {
    auto s=state({{1,cv::CAP_MSMF,true,{Frame::Bgr,Frame::Empty}}},{phone});auto cap=camera(s,1);cap.read();
    unavailable([&]{cap.read();});check(s->opens==1,"a failed sole phone camera is not retried indefinitely");
  }
  {
    auto s=state({});bool rejected=false;
    try{auto cap=camera(s,16);}catch(const std::runtime_error&){rejected=true;}
    check(rejected&&s->enumerations==0&&s->opens==0,"invalid saved indices are rejected before device access");
  }
  return checks;
}
