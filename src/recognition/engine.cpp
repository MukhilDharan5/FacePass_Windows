#include "facepass/vision.hpp"
#include <thread>
#include <algorithm>
#include <cmath>
#include <cstring>
namespace facepass {
Engine::Engine(const std::filesystem::path& models) {
  auto detector=models/L"face_detection_yunet_2023mar.onnx";
  auto recognizer=models/L"face_recognition_sface_2021dec.onnx";
  if(!std::filesystem::exists(detector)||!std::filesystem::exists(recognizer)) throw std::runtime_error("YuNet/SFace model files are missing; run scripts/setup.ps1");
  cv::setNumThreads(2);
  detector_=cv::FaceDetectorYN::create(narrow(detector.wstring()),"",{640,480},0.90f,0.3f,5000,cv::dnn::DNN_BACKEND_OPENCV,cv::dnn::DNN_TARGET_CPU);
  recognizer_=cv::FaceRecognizerSF::create(narrow(recognizer.wstring()),"",cv::dnn::DNN_BACKEND_OPENCV,cv::dnn::DNN_TARGET_CPU);
}
std::optional<Observation> Engine::observe(const cv::Mat& frame,std::wstring& reason) {
  if(frame.empty()||frame.type()!=CV_8UC3||frame.cols<80||frame.rows<80) { reason=L"Invalid camera frame"; return {}; }
  detector_->setInputSize(frame.size()); cv::Mat faces; detector_->detect(frame,faces);
  if(faces.rows!=1) { reason=faces.rows==0 ? L"No face detected. Move into view." : L"Only one person may be in view."; return {}; }
  auto f=faces.row(0); float width=f.at<float>(2),height=f.at<float>(3);
  if(width<90||height<90) { reason=L"Move closer to the camera"; return {}; }
  auto box=cv::Rect(static_cast<int>(f.at<float>(0)),static_cast<int>(f.at<float>(1)),static_cast<int>(width),static_cast<int>(height)) & cv::Rect(0,0,frame.cols,frame.rows);
  if(box.width<80||box.height<80) { reason=L"Keep your whole face in view"; return {}; }
  cv::Mat gray; cv::cvtColor(frame(box),gray,cv::COLOR_BGR2GRAY);
  Observation o; o.brightness=static_cast<float>(cv::mean(gray)[0]);
  cv::Mat lap; cv::Laplacian(gray,lap,CV_64F); cv::Scalar mean,sd; cv::meanStdDev(lap,mean,sd); o.sharpness=static_cast<float>(sd[0]*sd[0]);
  if(o.brightness<40||o.brightness>225||o.sharpness<35) { reason=L"Improve lighting and hold still; the image is too dark, bright, or blurred."; return {}; }
  float eye1=f.at<float>(4),eye2=f.at<float>(6),nose=f.at<float>(8);
  float eyes=std::abs(eye1-eye2);
  if(eyes<15) { reason=L"Face landmarks are not reliable"; return {}; }
  o.yaw=(nose-(eye1+eye2)*0.5f)/eyes;
  o.x=(f.at<float>(0)+width*0.5f)/frame.cols; o.y=(f.at<float>(1)+height*0.5f)/frame.rows;
  cv::Mat aligned,feature; recognizer_->alignCrop(frame,f,aligned); recognizer_->feature(aligned,feature);
  if(feature.total()!=EmbeddingSize||feature.type()!=CV_32F) throw std::runtime_error("Unexpected SFace embedding format");
  std::memcpy(o.embedding.data(),feature.ptr<float>(),sizeof(o.embedding));
  auto norm=cv::norm(feature); if(norm<1e-9) throw std::runtime_error("Invalid face embedding");
  for(auto& value:o.embedding) value=static_cast<float>(value/norm);
  reason=L"Face detected"; return o;
}
Template enroll(Camera& camera,Engine& engine,Profile profile,unsigned timeout,std::stop_token stop,const Progress& progress,const FrameSink& preview) {
  Template result; auto start=std::chrono::steady_clock::now(),last=start-std::chrono::seconds(1);
  Liveness live(profile); bool verified=profile==Profile::Instant;
  const std::array<const wchar_t*,SampleCount> prompts{L"Look straight ahead",L"Turn your nose toward the left of the preview",L"Turn your nose toward the right of the preview",L"Look straight ahead",L"Turn your nose toward the left of the preview",L"Turn your nose toward the right of the preview",L"Look straight ahead and hold still"};
  while(!stop.stop_requested()&&std::chrono::steady_clock::now()-start<std::chrono::seconds(timeout)) {
    auto frame=camera.read();if(preview)preview(frame); std::wstring reason; auto o=engine.observe(frame,reason); auto now=std::chrono::steady_clock::now();
    if(!o) { progress({Phase::Capturing,0,static_cast<unsigned>(result.samples.size()*100/SampleCount),reason}); std::this_thread::sleep_for(std::chrono::milliseconds(180)); continue; }
    if(!verified) { verified=live.update(*o,now); progress({Phase::Challenge,0,0,live.prompt()}); }
    else {
      auto n=result.samples.size();
      bool pose = n==1||n==4 ? o->yaw<-0.12f : n==2||n==5 ? o->yaw>0.12f : std::abs(o->yaw)<0.16f;
      bool identity = result.samples.empty() || cosine(o->embedding,result.samples.front())>=0.38f;
      if(pose&&identity&&now-last>=std::chrono::milliseconds(650)) { result.samples.push_back(o->embedding); last=now; }
      if(result.samples.size()==SampleCount) return result;
      progress({Phase::Capturing,0,static_cast<unsigned>(result.samples.size()*100/SampleCount),identity ? prompts[result.samples.size()] : L"Identity changed during enrollment; keep only your face in view."});
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(90));
  }
  if(stop.stop_requested()) throw std::runtime_error("Enrollment cancelled");
  throw std::runtime_error("Enrollment timed out before seven quality samples were captured");
}
Outcome recognize(Camera& camera,Engine& engine,const Template& enrolled,const Config& config,std::stop_token stop,const Progress& progress,const FrameSink& preview) {
  RecognitionGate gate(config); auto start=std::chrono::steady_clock::now(); float best=-1;
  while(!stop.stop_requested()&&std::chrono::steady_clock::now()-start<std::chrono::seconds(config.timeoutSeconds)) {
    auto frame=camera.read();if(preview)preview(frame); std::wstring reason; auto o=engine.observe(frame,reason);
    if(!o) { gate.reset(); progress({Phase::Capturing,0,0,reason}); std::this_thread::sleep_for(std::chrono::milliseconds(180)); continue; }
    float score=match(o->embedding,enrolled); best=std::max(best,score);
    if(gate.update(*o,score,std::chrono::steady_clock::now())) return {Phase::Recognized,score,100,DiagnosticRecognition::reason()};
    if(score>=gate.threshold()) progress({Phase::Challenge,score,0,gate.prompt()});
    else progress({Phase::Rejected,score,0,L"Face does not match this Windows account."});
    std::this_thread::sleep_for(std::chrono::milliseconds(90));
  }
  return {stop.stop_requested()?Phase::Cancelled:Phase::Rejected,best,0,stop.stop_requested()?L"Scan cancelled; webcam released.":config.profile==Profile::Instant?L"Face matching timed out. Use Windows PIN or password.":L"Recognition/liveness timed out. Use Windows PIN or password."};
}
}
