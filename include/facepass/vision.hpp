#pragma once
#include "types.hpp"
#include "platform.hpp"
#include <opencv2/opencv.hpp>
#include <opencv2/objdetect/face.hpp>
#include <optional>

namespace facepass {
std::vector<std::wstring> camera_names();
class Camera {
  cv::VideoCapture capture_;
  unsigned index_ = 0;
  bool delivered_ = false;
  bool fallback_ = false;
public:
  explicit Camera(unsigned index);
  cv::Mat read();
};
struct Observation {
  Embedding embedding{};
  float yaw = 0;
  float x = 0;
  float y = 0;
  float brightness = 0;
  float sharpness = 0;
};
class Engine {
  cv::Ptr<cv::FaceDetectorYN> detector_;
  cv::Ptr<cv::FaceRecognizerSF> recognizer_;
public:
  explicit Engine(const std::filesystem::path& models);
  std::optional<Observation> observe(const cv::Mat&, std::wstring& reason);
};
// Temporal/challenge heuristics only: replay and synthetic-video resistance are unverified.
class Liveness {
  Profile profile_;
  std::vector<int> challenge_;
  unsigned step_ = 0, stable_ = 0;
  std::chrono::steady_clock::time_point start_;
  float minYaw_ = 1, maxYaw_ = -1;
  bool center_ = false;
public:
  explicit Liveness(Profile, std::vector<int> challenge = {});
  bool update(const Observation&, std::chrono::steady_clock::time_point);
  std::wstring prompt() const;
};
// Shared by camera recognition and deterministic tests of acceptance timing.
class RecognitionGate {
  Config config_;
  Liveness live_;
  unsigned consistent_ = 0;
public:
  explicit RecognitionGate(const Config& config);
  float threshold() const;
  void reset();
  bool update(const Observation&, float similarity, std::chrono::steady_clock::time_point);
  std::wstring prompt() const { return live_.prompt(); }
};
using FrameSink=std::function<void(const cv::Mat&)>;
Template enroll(Camera&, Engine&, Profile, unsigned timeout, std::stop_token, const Progress&,const FrameSink& = {});
Outcome recognize(Camera&, Engine&, const Template&, const Config&, std::stop_token, const Progress&,const FrameSink& = {});
}
