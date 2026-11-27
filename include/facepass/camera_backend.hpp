#pragma once
#include <opencv2/core.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace facepass::detail {
struct CameraDevice {
  unsigned index = 0; // Media Foundation enumeration order.
  std::wstring name;
  std::wstring symbolicLink;
  bool windowsVirtual = false;
  std::optional<unsigned> directShowIndex;
};
// Transport seam lets tests exercise the production failover without camera hardware.
class CameraBackend {
public:
  virtual ~CameraBackend() = default;
  virtual std::vector<CameraDevice> devices() = 0;
  virtual bool open(unsigned index,int api) = 0;
  virtual bool read(cv::Mat& frame) = 0;
  virtual void release() = 0;
};
bool is_windows_virtual_camera(std::wstring_view name,bool virtualProperty);
}
