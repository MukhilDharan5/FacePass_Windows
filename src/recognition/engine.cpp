#include "facepass/vision.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
namespace facepass {
namespace {
// Bound YuNet's work independently of the camera resolution. SFace still uses
// the original pixels and landmarks, so alignment keeps the source detail.
constexpr int DetectionShortEdge=480,DetectionLongEdge=960;
cv::Mat improve_lighting(const cv::Mat& image,const cv::Ptr<cv::CLAHE>& contrast) {
  cv::Mat lab;cv::cvtColor(image,lab,cv::COLOR_BGR2Lab);
  std::vector<cv::Mat> channels;cv::split(lab,channels);
  const double brightness=cv::mean(channels[0])[0];
  if(brightness>=90)return image;
  const double gamma=std::clamp(std::log(110.0/255)/std::log(std::max(1.0,brightness)/255),0.35,1.0);
  cv::Mat lut(1,256,CV_8U);
  for(int value=0;value<256;++value)lut.at<uchar>(value)=cv::saturate_cast<uchar>(255*std::pow(value/255.0,gamma));
  cv::LUT(channels[0],lut,channels[0]);
  cv::Mat local;contrast->apply(channels[0],local);
  cv::addWeighted(channels[0],0.65,local,0.35,0,channels[0]);
  cv::merge(channels,lab);cv::Mat result;cv::cvtColor(lab,result,cv::COLOR_Lab2BGR);return result;
}
}
Engine::Engine(const std::filesystem::path& models) {
  auto detector=models/L"face_detection_yunet_2023mar.onnx";
  auto recognizer=models/L"face_recognition_sface_2021dec.onnx";
  if(!std::filesystem::exists(detector)||!std::filesystem::exists(recognizer)) throw std::runtime_error("YuNet/SFace model files are missing; run scripts/setup.ps1");
  cv::setNumThreads(2);
  detector_=cv::FaceDetectorYN::create(narrow(detector.wstring()),"",{DetectionShortEdge,DetectionShortEdge},0.90f,0.3f,5000,cv::dnn::DNN_BACKEND_OPENCV,cv::dnn::DNN_TARGET_CPU);
  recognizer_=cv::FaceRecognizerSF::create(narrow(recognizer.wstring()),"",cv::dnn::DNN_BACKEND_OPENCV,cv::dnn::DNN_TARGET_CPU);
  contrast_=cv::createCLAHE(2.0,{8,8});
}
std::optional<Observation> Engine::observe(const cv::Mat& frame,std::wstring& reason) {
  if(frame.empty()||frame.type()!=CV_8UC3||frame.cols<80||frame.rows<80) { reason=L"Invalid camera frame"; return {}; }
  const double scale=std::min({1.0,static_cast<double>(DetectionShortEdge)/std::min(frame.cols,frame.rows),
    static_cast<double>(DetectionLongEdge)/std::max(frame.cols,frame.rows)});
  cv::Mat small;
  if(scale<1)cv::resize(frame,small,{},scale,scale,cv::INTER_AREA);else small=frame;
  auto detection=improve_lighting(small,contrast_);
  detector_->setInputSize(detection.size()); cv::Mat faces; detector_->detect(detection,faces);
  if(faces.rows!=1) { reason=faces.rows==0 ? L"No face detected. Move into view." : L"Only one person may be in view."; return {}; }
  // YuNet returns x/y, width/height, five landmark pairs, then confidence.
  const float scaleX=static_cast<float>(frame.cols)/small.cols,scaleY=static_cast<float>(frame.rows)/small.rows;
  for(int column=0;column<14;++column)faces.at<float>(0,column)*=column%2==0?scaleX:scaleY;
  auto f=faces.row(0); float width=f.at<float>(2),height=f.at<float>(3);
  if(width<90||height<90) { reason=L"Move closer to the camera"; return {}; }
  auto box=cv::Rect(static_cast<int>(f.at<float>(0)),static_cast<int>(f.at<float>(1)),static_cast<int>(width),static_cast<int>(height)) & cv::Rect(0,0,frame.cols,frame.rows);
  if(box.width<80||box.height<80) { reason=L"Keep your whole face in view"; return {}; }
  cv::Mat gray; cv::cvtColor(frame(box),gray,cv::COLOR_BGR2GRAY);
  Observation o; o.brightness=static_cast<float>(cv::mean(gray)[0]);
  cv::Scalar mean,sd;cv::meanStdDev(gray,mean,sd);
  if(o.brightness>225) { reason=L"Reduce glare; the face image is overexposed."; return {}; }
  if(o.brightness<12||sd[0]<4) { reason=L"Add a little light; the camera needs visible face detail."; return {}; }
  // Correct only the detected face at source resolution. Raw signal checks above
  // prevent enhancement from treating a black/flat frame as usable face detail.
  auto faceImage=improve_lighting(frame(box),contrast_);
  cv::Mat quality;cv::cvtColor(faceImage,quality,cv::COLOR_BGR2GRAY);
  cv::Mat lap; cv::Laplacian(quality,lap,CV_64F); cv::meanStdDev(lap,mean,sd); o.sharpness=static_cast<float>(sd[0]*sd[0]);
  if(o.sharpness<35) { reason=L"Hold still; the face image is blurred."; return {}; }
  float eye1=f.at<float>(4),eye2=f.at<float>(6),nose=f.at<float>(8);
  float eyes=std::abs(eye1-eye2);
  if(eyes<15) { reason=L"Face landmarks are not reliable"; return {}; }
  o.yaw=(nose-(eye1+eye2)*0.5f)/eyes;
  o.x=(f.at<float>(0)+width*0.5f)/frame.cols; o.y=(f.at<float>(1)+height*0.5f)/frame.rows;
  cv::Mat aligned,feature; recognizer_->alignCrop(frame,f,aligned);
  aligned=improve_lighting(aligned,contrast_);recognizer_->feature(aligned,feature);
  if(feature.total()!=EmbeddingSize||feature.type()!=CV_32F) throw std::runtime_error("Unexpected SFace embedding format");
  std::memcpy(o.embedding.data(),feature.ptr<float>(),sizeof(o.embedding));
  auto norm=cv::norm(feature); if(norm<1e-9) throw std::runtime_error("Invalid face embedding");
  for(auto& value:o.embedding) value=static_cast<float>(value/norm);
  reason=L"Face detected"; return o;
}
Template enroll(Camera& camera,Engine& engine,Profile profile,unsigned timeout,std::stop_token stop,const Progress& progress,const FrameSink& preview) {
  Template result; auto start=std::chrono::steady_clock::now(),last=start-std::chrono::seconds(1);
  Liveness live(profile); bool verified=profile==Profile::Instant;
  auto cameraGeneration=camera.generation();
  const std::array<const wchar_t*,SampleCount> prompts{L"Look straight ahead",L"Turn your nose toward the left of the preview",L"Turn your nose toward the right of the preview",L"Look straight ahead",L"Turn your nose toward the left of the preview",L"Turn your nose toward the right of the preview",L"Look straight ahead and hold still"};
  while(!stop.stop_requested()&&std::chrono::steady_clock::now()-start<std::chrono::seconds(timeout)) {
    auto frame=camera.read();
    if(cameraGeneration!=camera.generation()) {
      cameraGeneration=camera.generation();
      for(auto& sample:result.samples)SecureZeroMemory(sample.data(),sizeof(sample));
      result.samples.clear();live=Liveness(profile);verified=profile==Profile::Instant;last=std::chrono::steady_clock::now()-std::chrono::seconds(1);
    }
    if(preview)preview(frame); std::wstring reason; auto o=engine.observe(frame,reason); auto now=std::chrono::steady_clock::now();
    if(!o) { progress({Phase::Capturing,0,static_cast<unsigned>(result.samples.size()*100/SampleCount),reason}); continue; }
    if(!verified) { verified=live.update(*o,now); progress({Phase::Challenge,0,0,live.prompt()}); }
    else {
      auto n=result.samples.size();
      bool pose = n==1||n==4 ? o->yaw<-0.12f : n==2||n==5 ? o->yaw>0.12f : std::abs(o->yaw)<0.16f;
      bool identity = result.samples.empty() || cosine(o->embedding,result.samples.front())>=0.38f;
      if(pose&&identity&&now-last>=std::chrono::milliseconds(650)) { result.samples.push_back(o->embedding); last=now; }
      if(result.samples.size()==SampleCount) return result;
      progress({Phase::Capturing,0,static_cast<unsigned>(result.samples.size()*100/SampleCount),identity ? prompts[result.samples.size()] : L"Identity changed during enrollment; keep only your face in view."});
    }
  }
  if(stop.stop_requested()) throw std::runtime_error("Enrollment cancelled");
  throw std::runtime_error("Enrollment timed out before seven quality samples were captured");
}
Outcome recognize(Camera& camera,Engine& engine,const Template& enrolled,const Config& config,std::stop_token stop,const Progress& progress,const FrameSink& preview) {
  RecognitionGate gate(config); auto start=std::chrono::steady_clock::now(); float best=-1;
  auto cameraGeneration=camera.generation();
  while(!stop.stop_requested()&&std::chrono::steady_clock::now()-start<std::chrono::seconds(config.timeoutSeconds)) {
    auto frame=camera.read();
    if(stop.stop_requested())break;
    if(cameraGeneration!=camera.generation()){cameraGeneration=camera.generation();gate.reset();best=-1;}
    std::wstring reason; auto o=engine.observe(frame,reason);
    if(!o) { gate.reset(); progress({Phase::Capturing,0,0,reason}); if(preview)preview(frame); continue; }
    float score=match(o->embedding,enrolled); best=std::max(best,score);
    if(gate.update(*o,score,std::chrono::steady_clock::now())) return {Phase::Recognized,score,100,DiagnosticRecognition::reason()};
    if(score>=gate.threshold()) progress({Phase::Challenge,score,0,gate.prompt()});
    else progress({Phase::Rejected,score,0,L"Face does not match this Windows account."});
    if(preview)preview(frame);
  }
  return {stop.stop_requested()?Phase::Cancelled:Phase::Rejected,best,0,stop.stop_requested()?L"Scan cancelled; webcam released.":config.profile==Profile::Instant?L"Face matching timed out. Use Windows PIN or password.":L"Recognition/liveness timed out. Use Windows PIN or password."};
}
}
