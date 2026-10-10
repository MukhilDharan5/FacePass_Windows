#include "facepass/vision.hpp"
#include <algorithm>
#include <cmath>
namespace facepass {
Liveness::Liveness(Profile profile,std::vector<int> challenge):profile_(profile),challenge_(std::move(challenge)),start_(std::chrono::steady_clock::now()) {
  if(challenge_.empty() && (profile==Profile::Balanced || profile==Profile::Strict)) {
    std::array<std::uint8_t,1> random{}; random_bytes(random);
    if(profile==Profile::Strict) for(unsigned bit=0;bit<3;++bit){challenge_.push_back((random[0]&(1u<<bit))?1:-1);challenge_.push_back(0);}
    else if(profile==Profile::Balanced) challenge_={(random[0]&1) ? -1 : 1,0};
  }
}
bool Liveness::update(const Observation& observation,std::chrono::steady_clock::time_point now) {
  if(profile_==Profile::Instant) return true;
  minYaw_=std::min(minYaw_,observation.yaw); maxYaw_=std::max(maxYaw_,observation.yaw);
  if(profile_==Profile::Convenience) return ++stable_>=10 && now-start_>=std::chrono::seconds(1);
  if(step_>=challenge_.size()) return now-start_>=std::chrono::milliseconds(1500);
  int expected=challenge_[step_];
  bool ok = expected==0 ? std::abs(observation.yaw)<0.13f : expected<0 ? observation.yaw<-0.20f : observation.yaw>0.20f;
  if(ok) { if(++stable_>=3) { ++step_; stable_=0; } } else stable_=0;
  return step_>=challenge_.size() && now-start_>=std::chrono::milliseconds(1500);
}
std::wstring Liveness::prompt() const {
  if(profile_==Profile::Instant) return L"Checking 2D face match...";
  if(profile_==Profile::Convenience) return L"Hold your face steady. Convenience offers very limited replay resistance.";
  if(step_>=challenge_.size()) return L"Challenge observed. Checking identity...";
  return challenge_[step_]==0 ? L"Look straight at the camera" : challenge_[step_]<0 ? L"Slowly turn your nose toward the left of the preview" : L"Slowly turn your nose toward the right of the preview";
}
RecognitionGate::RecognitionGate(const Config& config):config_(config),live_(config.profile) {}
float RecognitionGate::threshold() const {
  return std::max(config_.threshold,config_.profile==Profile::Strict ? 0.55f : config_.profile==Profile::Balanced ? 0.45f : 0.363f);
}
void RecognitionGate::reset() { consistent_=0;live_=Liveness(config_.profile); }
bool RecognitionGate::update(const Observation& observation,float similarity,std::chrono::steady_clock::time_point now) {
  if(!std::isfinite(similarity) || similarity<threshold()) { reset();return false; }
  ++consistent_;
  return live_.update(observation,now) && (config_.profile==Profile::Instant || consistent_>=5);
}
}
