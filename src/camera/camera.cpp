#include "facepass/vision.hpp"
#include <mfapi.h>
#include <mfidl.h>
#include <initguid.h>
#include <mfvirtualcamera.h>
#include <cfgmgr32.h>
#include <dshow.h>
#include <wrl/client.h>
#include <algorithm>
#include <cwctype>

namespace facepass {
namespace {
using Microsoft::WRL::ComPtr;
struct ComScope {
  HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
  ~ComScope(){if(SUCCEEDED(result))CoUninitialize();}
};
struct MfScope {
  HRESULT result=MFStartup(MF_VERSION,MFSTARTUP_LITE);
  ~MfScope(){if(SUCCEEDED(result))MFShutdown();}
};
struct Sources {
  IMFActivate** devices=nullptr;
  UINT32 count=0;
  ~Sources(){for(UINT32 i=0;i<count;++i)devices[i]->Release();CoTaskMemFree(devices);}
};
std::wstring attribute_string(IMFAttributes* attributes,const GUID& key) {
  wchar_t* value=nullptr;UINT32 length=0;
  if(FAILED(attributes->GetAllocatedString(key,&value,&length)))return {};
  std::wstring result(value,length);CoTaskMemFree(value);return result;
}
bool virtual_camera_property(const std::wstring& link) {
  if(link.empty())return false;
  DEVPROPTYPE type=0;DEVPROP_BOOLEAN value=DEVPROP_FALSE;ULONG size=sizeof(value);
  return CM_Get_Device_Interface_PropertyW(link.c_str(),&DEVPKEY_DeviceInterface_IsVirtualCamera,
    &type,reinterpret_cast<PBYTE>(&value),&size,0)==CR_SUCCESS
    && type==DEVPROP_TYPE_BOOLEAN && value==DEVPROP_TRUE;
}
std::vector<std::wstring> directshow_links() {
  std::vector<std::wstring> links;
  ComPtr<ICreateDevEnum> enumerator;ComPtr<IEnumMoniker> monikers;
  if(FAILED(CoCreateInstance(CLSID_SystemDeviceEnum,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&enumerator)))
    || enumerator->CreateClassEnumerator(CLSID_VideoInputDeviceCategory,&monikers,0)!=S_OK)return links;
  ComPtr<IMoniker> moniker;
  while(monikers->Next(1,&moniker,nullptr)==S_OK) {
    ComPtr<IPropertyBag> properties;VARIANT path;VariantInit(&path);
    if(SUCCEEDED(moniker->BindToStorage(nullptr,nullptr,IID_PPV_ARGS(&properties))))properties->Read(L"DevicePath",&path,nullptr);
    links.push_back(path.vt==VT_BSTR&&path.bstrVal?path.bstrVal:L"");
    VariantClear(&path);moniker.Reset();
  }
  return links;
}
std::vector<detail::CameraDevice> enumerate_cameras() {
  ComScope com;MfScope mf;std::vector<detail::CameraDevice> result;
  if(FAILED(mf.result))return result;
  ComPtr<IMFAttributes> attributes;Sources sources;
  if(FAILED(MFCreateAttributes(&attributes,1))
    || FAILED(attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID))
    || FAILED(MFEnumDeviceSources(attributes.Get(),&sources.devices,&sources.count)))return result;
  auto links=directshow_links();
  for(UINT32 i=0;i<sources.count;++i) {
    detail::CameraDevice device;device.index=i;
    device.name=attribute_string(sources.devices[i],MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME);
    if(device.name.empty())device.name=L"Camera "+std::to_wstring(i);
    device.symbolicLink=attribute_string(sources.devices[i],MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK);
    device.windowsVirtual=detail::is_windows_virtual_camera(device.name,virtual_camera_property(device.symbolicLink));
    // DirectShow and Media Foundation can enumerate in different orders. Match the
    // actual device path instead of opening another camera by index.
    if(!device.symbolicLink.empty()&&!device.windowsVirtual) {
      for(unsigned n=0;n<links.size();++n)if(_wcsicmp(links[n].c_str(),device.symbolicLink.c_str())==0){device.directShowIndex=n;break;}
    }
    result.push_back(std::move(device));
  }
  return result;
}
class OpenCvCameraBackend final : public detail::CameraBackend {
  ComScope com_;
  cv::VideoCapture capture_;
public:
  std::vector<detail::CameraDevice> devices() override { return enumerate_cameras(); }
  bool open(unsigned index,int api) override {
    if(!capture_.open(static_cast<int>(index),api))return false;
    capture_.set(cv::CAP_PROP_FRAME_WIDTH,640);
    capture_.set(cv::CAP_PROP_FRAME_HEIGHT,480);
    capture_.set(cv::CAP_PROP_BUFFERSIZE,1);
    return true;
  }
  bool read(cv::Mat& frame) override { return capture_.read(frame); }
  void release() override { capture_.release(); }
};
bool same_device(const detail::CameraDevice& a,const detail::CameraDevice& b) {
  if(!a.symbolicLink.empty()&&!b.symbolicLink.empty())return _wcsicmp(a.symbolicLink.c_str(),b.symbolicLink.c_str())==0;
  return a.index==b.index;
}
constexpr const char* CameraFailure="The selected camera source is unavailable. Check camera privacy, permissions, occupancy, and availability in this Windows session.";
}
bool detail::is_windows_virtual_camera(std::wstring_view name,bool virtualProperty) {
  if(virtualProperty)return true;
  // MFCreateVirtualCamera appends this suffix, including for user-named phones.
  // Keep a name fallback for systems that cannot query device-interface properties.
  constexpr std::wstring_view suffix=L"windows virtual camera";
  while(!name.empty()&&(std::iswspace(name.back())||name.back()==L')'))name.remove_suffix(1);
  if(name.size()<suffix.size())return false;
  auto ending=name.substr(name.size()-suffix.size());
  return std::equal(ending.begin(),ending.end(),suffix.begin(),[](wchar_t a,wchar_t b){return std::towlower(a)==b;});
}
std::vector<std::wstring> camera_names() {
  std::vector<std::wstring> names;
  for(const auto& device:enumerate_cameras())if(device.index<16)names.push_back(std::to_wstring(device.index)+L": "+device.name);
  return names;
}
Camera::Camera(unsigned index,CameraSource source):Camera(index,std::make_unique<OpenCvCameraBackend>(),source) {}
Camera::Camera(unsigned index,std::unique_ptr<detail::CameraBackend> backend,CameraSource source):backend_(std::move(backend)),source_(source) {
  if(index>15)throw std::runtime_error("Camera index must be 0..15");
  if(!backend_)throw std::runtime_error("Camera backend is missing");
  if(static_cast<unsigned>(source_)>static_cast<unsigned>(CameraSource::Both))throw std::runtime_error("Invalid camera source");
  auto devices=backend_->devices();selected_.index=index;selected_.name=L"Camera "+std::to_wstring(index);
  auto found=std::find_if(devices.begin(),devices.end(),[&](const auto& device){return device.index==index;});
  if(found!=devices.end())selected_=*found;
  auto allowed=[&](const detail::CameraDevice& device) {
    return source_==CameraSource::Both || (source_==CameraSource::PhoneVirtual)==device.windowsVirtual;
  };
  if(source_!=CameraSource::Both) {
    if(!devices.empty()&&(found==devices.end()||!allowed(selected_))) {
      auto candidate=std::find_if(devices.begin(),devices.end(),allowed);
      if(candidate==devices.end())throw std::runtime_error(CameraFailure);
      selected_=*candidate;
    }
    if(devices.empty())throw std::runtime_error(CameraFailure);
  }
  if(devices.empty())selected_.directShowIndex=index;
  attempts_.push_back({selected_,cv::CAP_MSMF,selected_.index});
  if(!selected_.windowsVirtual&&selected_.directShowIndex)attempts_.push_back({selected_,cv::CAP_DSHOW,*selected_.directShowIndex});
  if(!open_next())throw std::runtime_error(CameraFailure);
}
bool Camera::open_next() {
  backend_->release();
  while(true) {
    if(next_==attempts_.size()) {
      if(virtualsQueued_)return false;
      virtualsQueued_=true;
      if(source_==CameraSource::Windows)return false;
      // Refresh after failure: devices can become available after capture starts.
      for(const auto& device:backend_->devices()) {
        bool alternateType=source_==CameraSource::PhoneVirtual
          ? device.windowsVirtual
          : device.windowsVirtual || selected_.windowsVirtual;
        if(alternateType&&!same_device(device,selected_)) {
          attempts_.push_back({device,cv::CAP_MSMF,device.index});
          if(!device.windowsVirtual&&device.directShowIndex)attempts_.push_back({device,cv::CAP_DSHOW,*device.directShowIndex});
        }
      }
      if(next_==attempts_.size())return false;
    }
    const auto& attempt=attempts_[next_++];
    try {
      if(backend_->open(attempt.index,attempt.api)){active_=attempt.device;++generation_;return true;}
    }catch(const cv::Exception&){} // A driver exception is also a capture failure.
    backend_->release();
  }
}
cv::Mat Camera::read() {
  while(true) {
    cv::Mat frame;bool read=false;
    try {read=backend_->read(frame);}catch(const cv::Exception&){}
    if(read&&!frame.empty()&&(frame.type()==CV_8UC3||frame.type()==CV_8UC4)) {
      if(frame.cols>1920||frame.rows>1080)cv::resize(frame,frame,{640,480});
      if(frame.channels()==4)cv::cvtColor(frame,frame,cv::COLOR_BGRA2BGR);
      return frame;
    }
    if(!open_next())throw std::runtime_error(CameraFailure);
  }
}
}
