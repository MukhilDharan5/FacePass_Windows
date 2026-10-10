#pragma once
#include "vision.hpp"
namespace facepass {
enum class CaptureKind : unsigned { Enroll, Recognize, Preview };
using PreviewSink=std::function<void(std::span<const std::uint8_t>)>;
struct CaptureResult { Outcome outcome; Template enrolled; };
// The parent owns inference results and the process lifetime. No public IPC is
// exposed by the worker; only explicitly inherited private kernel handles.
CaptureResult supervised_capture(CaptureKind,const Config&,const Template&,std::stop_token,const Progress&,const PreviewSink& = {},bool testHang=false);
struct CaptureShared {
  unsigned magic=ProtocolMagic;
  Config config{};
  CaptureKind kind=CaptureKind::Preview;
  unsigned inputCount=0,outputCount=0,done=0,previewAllowed=0;
  std::array<Embedding,SampleCount> input{},output{};
  Phase phase=Phase::Capturing;
  float similarity=0;
  unsigned progress=0,previewSize=0;
  wchar_t message[512]{};
  std::array<std::uint8_t,PreviewCapacity> preview{};
};
}
