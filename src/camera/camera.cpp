#include "facepass/vision.hpp"
#include <mfapi.h>
#include <mfidl.h>
namespace facepass {
std::vector<std::wstring> camera_names() {
  std::vector<std::wstring> names;
  if(FAILED(MFStartup(MF_VERSION,MFSTARTUP_LITE)))return names;
  IMFAttributes* attributes=nullptr;IMFActivate** devices=nullptr;UINT32 count=0;
  if(SUCCEEDED(MFCreateAttributes(&attributes,1))) {
    attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if(SUCCEEDED(MFEnumDeviceSources(attributes,&devices,&count))) {
      for(UINT32 i=0;i<count&&i<16;++i){wchar_t* name=nullptr;UINT32 size=0;if(SUCCEEDED(devices[i]->GetAllocatedString(MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,&name,&size))){names.push_back(std::to_wstring(i)+L": "+name);CoTaskMemFree(name);}else names.push_back(L"Camera "+std::to_wstring(i));}
      for(UINT32 i=0;i<count;++i)devices[i]->Release();CoTaskMemFree(devices);
    }attributes->Release();
  }MFShutdown();return names;
}
Camera::Camera(unsigned index):index_(index) {
  if(index>15) throw std::runtime_error("Camera index must be 0..15");
  if(!capture_.open(static_cast<int>(index),cv::CAP_MSMF)) {
    fallback_=true;
    if(!capture_.open(static_cast<int>(index),cv::CAP_DSHOW)) throw std::runtime_error("Cannot open webcam. Check camera permissions, other applications, or Session 0 restrictions.");
  }
  capture_.set(cv::CAP_PROP_FRAME_WIDTH,640);
  capture_.set(cv::CAP_PROP_FRAME_HEIGHT,480);
  capture_.set(cv::CAP_PROP_BUFFERSIZE,1);
}
cv::Mat Camera::read() {
  cv::Mat frame;
  if(!capture_.read(frame)||frame.empty()) {
    if(!delivered_&&!fallback_) {
      capture_.release();fallback_=true;
      if(capture_.open(static_cast<int>(index_),cv::CAP_DSHOW)) {
        capture_.set(cv::CAP_PROP_FRAME_WIDTH,640);capture_.set(cv::CAP_PROP_FRAME_HEIGHT,480);
        capture_.read(frame);
      }
    }
    if(frame.empty())throw std::runtime_error("Webcam disconnected or capture failed (Media Foundation and DirectShow). Check privacy switch, Windows permissions and camera occupancy.");
  }
  delivered_=true;
  if(frame.cols>1920||frame.rows>1080) cv::resize(frame,frame,{640,480});
  if(frame.channels()==4) cv::cvtColor(frame,frame,cv::COLOR_BGRA2BGR);
  if(frame.channels()!=3) throw std::runtime_error("Unsupported webcam pixel format");
  return frame;
}
}
