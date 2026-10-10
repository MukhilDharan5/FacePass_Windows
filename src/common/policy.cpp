#include "facepass/types.hpp"
#include <algorithm>
#include <cmath>
namespace facepass {
bool valid_config(const Config& c) {
  return c.version==1 && static_cast<unsigned>(c.mode)<=2 && static_cast<unsigned>(c.profile)<=static_cast<unsigned>(Profile::Instant) && c.camera<=15
    && c.attempts>=1 && c.attempts<=10 && c.cooldownSeconds>=5 && c.cooldownSeconds<=600
    && c.timeoutSeconds>=5 && c.timeoutSeconds<=60 && std::isfinite(c.threshold) && c.threshold>=0.363f && c.threshold<=0.85f && c.requireAfterRestart<=1;
}
Config unlock_config(Config config) {
  if(config.profile!=Profile::Instant) {
    config.profile=Profile::Strict;
    config.threshold=std::max(config.threshold,0.55f);
  }
  return config;
}
float cosine(const Embedding& a, const Embedding& b) {
  double dot=0, na=0, nb=0;
  for(std::size_t i=0;i<a.size();++i) { if(!std::isfinite(a[i])||!std::isfinite(b[i])) return -1; dot+=static_cast<double>(a[i])*b[i]; na+=static_cast<double>(a[i])*a[i]; nb+=static_cast<double>(b[i])*b[i]; }
  if(na<1e-12||nb<1e-12) return -1;
  return static_cast<float>(std::clamp(dot/std::sqrt(na*nb),-1.0,1.0));
}
float match(const Embedding& probe, const Template& enrolled) {
  if(enrolled.samples.empty()) return -1;
  std::vector<float> scores; for(const auto& sample:enrolled.samples) scores.push_back(cosine(probe,sample));
  // Require agreement with most enrollment samples; a single outlier cannot grant a match.
  std::sort(scores.begin(),scores.end()); return scores[(scores.size()-1)/2];
}
bool RetryPolicy::allowed(std::chrono::steady_clock::time_point now) const { return now>=until_; }
void RetryPolicy::failed(const Config& c, std::chrono::steady_clock::time_point now) { if(now>=until_ && until_!=std::chrono::steady_clock::time_point{}) { failures_=0; until_={}; } if(++failures_>=c.attempts) until_=now+std::chrono::seconds(c.cooldownSeconds); }
void RetryPolicy::succeeded() { failures_=0; until_={}; }
unsigned RetryPolicy::remaining(std::chrono::steady_clock::time_point now) const { return now>=until_ ? 0 : static_cast<unsigned>(std::chrono::duration_cast<std::chrono::seconds>(until_-now).count()+1); }
}
