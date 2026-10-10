#include "facepass/ipc.hpp"
#include "facepass/vision.hpp"
#include "facepass/capture.hpp"
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <shellapi.h>
#include <map>
#include <mutex>
#include <thread>
#include <iomanip>
#include <sstream>
using namespace facepass;
namespace {
enum Id {NavOverview=100,NavAuth,NavFace,NavAdvanced,ToggleTheme=110,Apply=200,Enroll=201,Delete=202,Scan=203,Cancel=204,Preview=205,Refresh=206,Recovery=207,Logs=208,SessionEnroll=209,SavePassword=210,RemovePassword=211,ModeControl=300,ProfileControl=301,CameraControl=302,ThresholdControl=303,AttemptsControl=304,CooldownControl=305,TimeoutControl=306,RestartControl=307};
LRESULT CALLBACK capture_window_proc(HWND,UINT,WPARAM,LPARAM);
struct App {
  HWND window=nullptr; HINSTANCE instance=nullptr;
  bool demo=false,dark=false,busy=false,previewing=false,configured=false;
  int page=0; unsigned dpi=96;
  HFONT font=nullptr,titleFont=nullptr,smallFont=nullptr;
  HBRUSH bg=nullptr,field=nullptr;
  std::vector<HWND> controls;
  std::map<int,HWND> byId;
  std::wstring status=L"Connecting to FacePass...";
  Response response{};
  std::jthread task;
  std::mutex mutex;
  Response pending{}; std::wstring error;
  bool pendingOk=false;
  bool cancelQueued=false,captureDismissed=false;
  HWND captureWindow=nullptr;
  cv::Mat captureImage;
  std::vector<BYTE> previewPacket;
  int s(int value) const {return MulDiv(value,static_cast<int>(dpi),96);}
  COLORREF background()const{return dark?RGB(27,30,35):RGB(246,248,251);}
  COLORREF foreground()const{return dark?RGB(235,239,245):RGB(31,40,54);}
  COLORREF muted()const{return dark?RGB(166,178,195):RGB(88,104,124);}
  void palette(){if(bg)DeleteObject(bg);if(field)DeleteObject(field);bg=CreateSolidBrush(background());field=CreateSolidBrush(dark?RGB(37,42,49):RGB(255,255,255));BOOL yes=dark;DwmSetWindowAttribute(window,20,&yes,sizeof(yes));}
  HWND control(const wchar_t* type,const std::wstring& text,int id,int x,int y,int w,int h,DWORD style=0) {
    auto c=CreateWindowExW(wcscmp(type,L"EDIT")==0?WS_EX_CLIENTEDGE:0,type,text.c_str(),WS_CHILD|WS_VISIBLE|style,s(x),s(y),s(w),s(h),window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),instance,nullptr);
    SendMessageW(c,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);controls.push_back(c);if(id)byId[id]=c;return c;
  }
  void label(const std::wstring& text,int x,int y,int w=600,int h=26){control(L"STATIC",text,0,x,y,w,h,SS_LEFT);}
  void button(const std::wstring& text,int id,int x,int y,int w=155){control(L"BUTTON",text,id,x,y,w,36,BS_OWNERDRAW|WS_TABSTOP);}
  void combo(int id,const std::vector<std::wstring>& items,int selected,int x,int y,int w=240) {
    auto c=control(L"COMBOBOX",L"",id,x,y,w,240,CBS_DROPDOWNLIST|WS_VSCROLL|WS_TABSTOP);
    for(const auto& item:items)SendMessageW(c,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(item.c_str()));SendMessageW(c,CB_SETCURSEL,selected,0);
  }
  void clear(){for(auto c:controls)DestroyWindow(c);controls.clear();byId.clear();}
  void render() {
    clear();
    button(L"Overview",NavOverview,22,120,178);button(L"Authentication",NavAuth,22,168,178);button(L"Face and camera",NavFace,22,216,178);button(L"Diagnostics",NavAdvanced,22,264,178);
    button(dark?L"Light appearance":L"Dark appearance",ToggleTheme,22,592,178);
    auto& c=response.config;
    if(page==0) {
      label(L"Optional face recognition",246,122,640,30);
      label(L"Windows PIN and password remain available as fallback.",246,160);
      label(response.passwordBackedBackend?L"Face unlock: enabled using Windows authentication":response.backendAvailable?L"Passwordless backend: enabled and loaded (local console unlock)":L"Face unlock: not enabled",246,206,640,32);
      label(demo?L"Service target: per-user demonstration server":L"Service target: Windows service (LocalService)",246,253);
      label(std::wstring(L"Face profile: ")+(response.enrolled?L"enrolled and encrypted":L"not enrolled"),246,295);
      label(std::wstring(L"Activation: ")+(c.mode==Mode::Off?L"Off":c.mode==Mode::Manual?L"Manual":L"Automatic on console session lock"),246,337);
      label(std::wstring(L"Camera activity: ")+(response.cameraActive?L"capturing":L"idle"),246,379);
      label(L"RGB webcam recognition is vulnerable to replay and synthetic video.",246,435,640,48);
      button(L"Refresh status",Refresh,246,515);button(L"Test recognition",Scan,414,515);button(L"Cancel capture",Cancel,582,515);
    } else if(page==1) {
      label(L"Activation mode",246,124);combo(ModeControl,{L"Off",L"Manual",L"Automatic"},static_cast<int>(c.mode),246,154,295);
      label(L"Manual scans when selected. Automatic scans on a console lock event.",246,200,640,44);
      label(L"Failed attempt limit",246,268,240);control(L"EDIT",std::to_wstring(c.attempts),AttemptsControl,550,263,110,30,ES_NUMBER|WS_TABSTOP);
      label(L"Cooldown (seconds)",246,312,240);control(L"EDIT",std::to_wstring(c.cooldownSeconds),CooldownControl,550,307,110,30,ES_NUMBER|WS_TABSTOP);
      label(L"Scan timeout (seconds)",246,356,240);control(L"EDIT",std::to_wstring(c.timeoutSeconds),TimeoutControl,550,351,110,30,ES_NUMBER|WS_TABSTOP);
      auto check=control(L"BUTTON",L"Require a Windows sign-in after service restart",RestartControl,246,408,610,32,BS_AUTOCHECKBOX|WS_TABSTOP);SendMessageW(check,BM_SETCHECK,c.requireAfterRestart?BST_CHECKED:BST_UNCHECKED,0);
      label(std::wstring(L"Windows password: ")+(response.credentialSaved?L"saved encrypted on this laptop":L"not saved"),246,456,640,26);
      button(response.credentialSaved?L"Update saved password":L"Save Windows password",SavePassword,246,490,230);
      button(L"Remove saved password",RemovePassword,490,490,230);
      button(L"Save preferences",Apply,246,536,180);
      label(L"Face unlock submits the saved Microsoft-account password to Windows.\nUse your account password, not your PIN. Remove it here at any time.",246,584,640,46);
    } else if(page==2) {
      label(L"Camera",246,124,170);
      auto names=camera_names();if(names.empty())names={L"Camera 0 (no camera enumerated)"};
      while(names.size()<=c.camera)names.push_back(L"Camera "+std::to_wstring(names.size()));
      combo(CameraControl,names,static_cast<int>(c.camera),450,120,420);
      label(L"Recognition profile",246,175,190);combo(ProfileControl,{L"Convenience (temporal only)",L"Balanced (short random challenge)",L"Strict (random multi-step challenge)",L"Instant (2D match; no challenges)"},static_cast<int>(c.profile),450,172,420);
      label(L"Cosine threshold (0.363 - 0.85)",246,228,290);
      std::wostringstream threshold;threshold<<std::fixed<<std::setprecision(3)<<c.threshold;control(L"EDIT",threshold.str(),ThresholdControl,620,223,120,30,WS_TABSTOP);
      label(L"Instant unlocks on the first 2D match; a photo or video can unlock.\nOther profiles use Strict for Windows unlock. Higher thresholds reject more faces.",246,269,640,54);
      button(L"Save preferences",Apply,246,332,180);button(L"Camera preview",Preview,444,332,180);
      button(response.enrolled?L"Re-enroll face":L"Enroll face",Enroll,246,394,180);button(L"Delete profile",Delete,444,394,180);
      button(L"Use recent sign-in",SessionEnroll,642,394,200);
      button(L"Test recognition",Scan,246,451,180);button(L"Cancel capture",Cancel,444,451,180);
      label(L"Use recent sign-in to enroll within two minutes of native Windows sign-in,\nor Enroll face for transient password verification. Follow the live preview.\nSeven encrypted samples are saved; camera images remain in memory.",246,517,660,78);
    } else {
      label(L"Service and security diagnostics",246,124);
      label(L"Face unlock: saved encrypted Microsoft-account password; Windows authenticates.\nIPC: verified Windows service; OS client identity; one-use face approval.\nStorage: encrypted templates and optional encrypted account password.\nCapture: supervised worker; cancellation and hard capture deadline.\nRecognition: Instant skips liveness; other unlock profiles use Strict challenges.\nConsole unlock only; boot logon and RDP are unsupported.",246,174,640,186);
      label(L"Recovery: select Windows PIN/password. Remove only the FacePass\nprovider registration if the demo tile causes trouble. See recovery.md.",246,388,640,75);
      button(L"Open recovery guide",Recovery,246,505,205);button(L"Windows event logs",Logs,470,505,205);
      button(L"Refresh status",Refresh,246,557,205);
    }
    InvalidateRect(window,nullptr,TRUE);
  }
  std::wstring value(int id) { wchar_t text[100]{};GetWindowTextW(byId.at(id),text,100);return text; }
  void show_capture(std::span<const BYTE> jpeg) {
    if(jpeg.empty() || captureDismissed)return;
    auto decoded=cv::imdecode(std::vector<BYTE>(jpeg.begin(),jpeg.end()),cv::IMREAD_COLOR);
    if(decoded.empty())return;
    cv::cvtColor(decoded,captureImage,cv::COLOR_BGR2BGRA);
    if(!captureWindow) {
      WNDCLASSW wc{};wc.lpfnWndProc=capture_window_proc;wc.hInstance=instance;wc.lpszClassName=L"FacePassCaptureView";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);RegisterClassW(&wc);
      captureWindow=CreateWindowExW(0,wc.lpszClassName,L"FacePass live capture",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,s(660),s(580),window,nullptr,instance,this);
      ShowWindow(captureWindow,SW_SHOW);
    }
    InvalidateRect(captureWindow,nullptr,FALSE);
  }
  void perform(Operation op, bool poll=false, std::optional<Config> config={}, Handle auth={},std::optional<WindowsCredential> credential={}) {
    if(busy) return;
    if(task.joinable())task.join();if(op==Operation::Enroll||op==Operation::Recognize)captureDismissed=false;busy=true;status=L"Contacting FacePass...";InvalidateRect(window,nullptr,FALSE);
    task=std::jthread([this,op,poll,config,auth=std::move(auth),credential=std::move(credential)](std::stop_token) {
      Response result;std::wstring problem;bool ok=false;
      try {Request r;r.operation=op;if(config)r.config=*config;if(credential)r.windowsCredential=*credential;result=call(r,demo,auth?auth.get():nullptr);ok=true;}catch(const std::exception& ex){problem=widen(ex.what());}
      {std::lock_guard lock(mutex);pending=result;error=problem;pendingOk=ok;}
      PostMessageW(window,WM_APP+2,poll?1:0,0);
    });
  }
  void save() {
    try {
      Config c=response.config;
      if(page==1) {c.mode=static_cast<Mode>(SendMessageW(byId.at(ModeControl),CB_GETCURSEL,0,0));c.attempts=std::stoul(value(AttemptsControl));c.cooldownSeconds=std::stoul(value(CooldownControl));c.timeoutSeconds=std::stoul(value(TimeoutControl));c.requireAfterRestart=SendMessageW(byId.at(RestartControl),BM_GETCHECK,0,0)==BST_CHECKED;}
      if(page==2) {c.camera=static_cast<unsigned>(SendMessageW(byId.at(CameraControl),CB_GETCURSEL,0,0));c.profile=static_cast<Profile>(SendMessageW(byId.at(ProfileControl),CB_GETCURSEL,0,0));c.threshold=std::stof(value(ThresholdControl));}
      if(!valid_config(c))throw std::runtime_error("Use attempts 1..10, cooldown 5..600, timeout 5..60, and threshold 0.363..0.85.");
      perform(Operation::Configure,false,c);
    }catch(const std::exception& ex){MessageBoxW(window,widen(ex.what()).c_str(),L"Invalid preferences",MB_OK|MB_ICONWARNING);}
  }
  void preview() {
    if(previewing||busy||response.cameraActive)return;
    if(response.config.mode==Mode::Off){MessageBoxW(window,L"Save Manual or Automatic mode before opening the camera.",L"Camera is disabled",MB_OK);return;}
    if(task.joinable())task.join();captureDismissed=false;previewing=true;busy=true;status=L"Camera preview is active for up to one minute; close the preview or press Escape to stop.";InvalidateRect(window,nullptr,FALSE);
    Config config=response.config;config.timeoutSeconds=60;
    task=std::jthread([this,config](std::stop_token stop){
      std::wstring problem;
      try{supervised_capture(CaptureKind::Preview,config,{},stop,{},[this](std::span<const BYTE> bytes){ {std::lock_guard lock(mutex);previewPacket.assign(bytes.begin(),bytes.end());}PostMessageW(window,WM_APP+4,0,0); });}catch(const std::exception& ex){if(!stop.stop_requested())problem=widen(ex.what());}
      {std::lock_guard lock(mutex);error=problem;pendingOk=false;}
      PostMessageW(window,WM_APP+3,0,0);
    });
  }
  void command(int id) {
    if(id>=NavOverview&&id<=NavAdvanced){page=id-NavOverview;render();return;}
    if(id==ToggleTheme){dark=!dark;palette();render();return;}
    if(id==Apply){save();return;}
    if(id==Preview){preview();return;}
    if(id==Recovery){ShellExecuteW(window,L"open",(executable_dir()/L"docs"/L"recovery.md").c_str(),nullptr,nullptr,SW_SHOWNORMAL);return;}
    if(id==Logs){ShellExecuteW(window,L"open",L"eventvwr.msc",nullptr,nullptr,SW_SHOWNORMAL);return;}
    if(id==Cancel && previewing){task.request_stop();return;}
    if(id==Cancel && busy){cancelQueued=true;return;}
    if(busy)return;
    if(id==Refresh)perform(Operation::Status);
    if(id==Scan)perform(Operation::Recognize,true);
    if(id==Cancel)perform(Operation::Cancel,true);
    if(id==Delete&&MessageBoxW(window,L"Delete this account's face profile and saved Windows password?",L"Delete face profile",MB_YESNO|MB_ICONQUESTION)==IDYES)perform(Operation::DeleteProfile);
    if(id==SavePassword) {
      try {
        if(demo||!response.passwordBackedBackend)throw std::runtime_error("Open Settings from the installed FacePass service with password-backed unlock enabled.");
        auto verified=prompt_windows_credential(window,true);
        perform(Operation::SaveWindowsCredential,false,{},std::move(verified.token),verified.credential);
      }catch(const std::exception& ex){MessageBoxW(window,widen(ex.what()).c_str(),L"Save Windows password",MB_OK|MB_ICONWARNING);}
    }
    if(id==RemovePassword)perform(Operation::DeleteWindowsCredential);
    if(id==Enroll || id==SessionEnroll) {
      try {if(response.config.mode==Mode::Off)throw std::runtime_error("Save Manual or Automatic mode before enrollment.");auto auth=id==SessionEnroll?recent_session_authentication():reauthenticate(window);perform(Operation::Enroll,true,{},std::move(auth));}catch(const std::exception& ex){MessageBoxW(window,widen(ex.what()).c_str(),L"Enrollment verification",MB_OK|MB_ICONWARNING);}
    }
  }
  void paint() {
    PAINTSTRUCT ps{};HDC dc=BeginPaint(window,&ps);RECT rect{};GetClientRect(window,&rect);FillRect(dc,&rect,bg);
    HBRUSH sidebar=CreateSolidBrush(dark?RGB(22,25,30):RGB(235,239,245));RECT side{0,0,s(218),rect.bottom};FillRect(dc,&side,sidebar);DeleteObject(sidebar);
    SetBkMode(dc,TRANSPARENT);SetTextColor(dc,foreground());SelectObject(dc,titleFont);
    RECT brand{s(22),s(30),s(205),s(72)};DrawTextW(dc,L"FacePass",-1,&brand,DT_LEFT|DT_SINGLELINE);
    const wchar_t* headings[]={L"Overview",L"Authentication",L"Face and camera",L"Diagnostics"};RECT title{s(246),s(30),rect.right-s(28),s(70)};DrawTextW(dc,headings[page],-1,&title,DT_SINGLELINE);
    SelectObject(dc,smallFont);SetTextColor(dc,muted());RECT sub{s(246),s(78),rect.right-s(28),s(104)};DrawTextW(dc,demo?L"Local face recognition demonstration":response.passwordBackedBackend?L"Face unlock using your saved Windows password":response.backendAvailable?L"Custom passwordless backend · VM validation required":L"Native Windows settings · backend not enabled/loaded",-1,&sub,DT_SINGLELINE);
    RECT line{s(246),s(625),rect.right-s(28),s(626)};HBRUSH rule=CreateSolidBrush(dark?RGB(65,73,86):RGB(209,217,230));FillRect(dc,&line,rule);DeleteObject(rule);
    RECT state{s(246),s(642),rect.right-s(28),s(716)};SetTextColor(dc,foreground());SelectObject(dc,font);DrawTextW(dc,status.c_str(),-1,&state,DT_WORDBREAK);
    EndPaint(window,&ps);
  }
  void draw_button(const DRAWITEMSTRUCT* item) {
    if(item->CtlType!=ODT_BUTTON)return;
    bool selected=item->CtlID==static_cast<UINT>(NavOverview+page),pressed=item->itemState&ODS_SELECTED;
    auto color=selected?RGB(31,102,182):pressed?(dark?RGB(56,67,84):RGB(221,231,245)):(dark?RGB(38,45,57):RGB(255,255,255));
    HBRUSH brush=CreateSolidBrush(color);FillRect(item->hDC,&item->rcItem,brush);DeleteObject(brush);SetBkMode(item->hDC,TRANSPARENT);SetTextColor(item->hDC,selected?RGB(255,255,255):foreground());SelectObject(item->hDC,font);
    wchar_t text[128]{};GetWindowTextW(item->hwndItem,text,128);RECT r=item->rcItem;DrawTextW(item->hDC,text,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    if(item->itemState&ODS_FOCUS){InflateRect(&r,-3,-3);DrawFocusRect(item->hDC,&r);}
  }
};
LRESULT CALLBACK capture_window_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
  auto app=reinterpret_cast<App*>(GetWindowLongPtrW(window,GWLP_USERDATA));
  if(message==WM_NCCREATE){app=static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(app));}
  if(!app)return DefWindowProcW(window,message,w,l);
  if(message==WM_PAINT) {
    PAINTSTRUCT paint{};HDC dc=BeginPaint(window,&paint);RECT area{};GetClientRect(window,&area);FillRect(dc,&area,app->bg);
    if(!app->captureImage.empty()) {
      BITMAPINFO bitmap{};bitmap.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bitmap.bmiHeader.biWidth=app->captureImage.cols;bitmap.bmiHeader.biHeight=-app->captureImage.rows;bitmap.bmiHeader.biPlanes=1;bitmap.bmiHeader.biBitCount=32;bitmap.bmiHeader.biCompression=BI_RGB;
      int width=static_cast<int>(area.right),height=std::max(1,std::min(static_cast<int>(area.bottom)-app->s(110),width*3/4));SetStretchBltMode(dc,HALFTONE);
      StretchDIBits(dc,0,0,width,height,0,0,app->captureImage.cols,app->captureImage.rows,app->captureImage.data,&bitmap,DIB_RGB_COLORS,SRCCOPY);
      RECT caption{app->s(16),height+app->s(12),area.right-app->s(16),area.bottom};SetBkMode(dc,TRANSPARENT);SetTextColor(dc,app->foreground());SelectObject(dc,app->font);DrawTextW(dc,app->status.c_str(),-1,&caption,DT_WORDBREAK);
    }
    EndPaint(window,&paint);return 0;
  }
  if(message==WM_CLOSE || (message==WM_KEYDOWN && w==VK_ESCAPE)){app->captureDismissed=true;app->command(Cancel);DestroyWindow(window);return 0;}
  if(message==WM_DESTROY){app->captureWindow=nullptr;app->captureImage.release();return 0;}
  return DefWindowProcW(window,message,w,l);
}
LRESULT CALLBACK window_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
  auto app=reinterpret_cast<App*>(GetWindowLongPtrW(window,GWLP_USERDATA));
  if(message==WM_NCCREATE){app=static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);app->window=window;SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(app));}
  if(!app)return DefWindowProcW(window,message,w,l);
  switch(message){
  case WM_COMMAND:if(HIWORD(w)==BN_CLICKED)app->command(LOWORD(w));return 0;
  case WM_PAINT:app->paint();return 0;
  case WM_ERASEBKGND:return 1;
  case WM_DRAWITEM:app->draw_button(reinterpret_cast<DRAWITEMSTRUCT*>(l));return TRUE;
  case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:case WM_CTLCOLORLISTBOX:{auto dc=reinterpret_cast<HDC>(w);SetTextColor(dc,app->foreground());SetBkColor(dc,app->background());return reinterpret_cast<LRESULT>(message==WM_CTLCOLOREDIT?app->field:app->bg);}
  case WM_TIMER:if(w==1&&!app->busy&&!app->previewing)app->perform(Operation::Status,true);return 0;
  case WM_APP+2:{
    KillTimer(window,1);bool rerender=!app->configured;
    {std::lock_guard lock(app->mutex);if(app->pendingOk){rerender=rerender||app->response.enrolled!=app->pending.enrolled||app->response.credentialSaved!=app->pending.credentialSaved||app->response.passwordBackedBackend!=app->pending.passwordBackedBackend||app->response.backendAvailable!=app->pending.backendAvailable||app->response.config.mode!=app->pending.config.mode;app->response=app->pending;app->status=app->response.message;app->configured=true;}else app->status=app->error+L". Start the service or the per-user demo server.";}
    app->busy=false;if(rerender)app->render();InvalidateRect(window,nullptr,FALSE);
    if(app->response.previewSize)app->show_capture({app->response.preview.data(),app->response.previewSize});
    if(!app->response.cameraActive && app->captureWindow && !app->previewing)DestroyWindow(app->captureWindow);
    if(app->captureWindow)InvalidateRect(app->captureWindow,nullptr,FALSE);
    if(app->cancelQueued){app->cancelQueued=false;app->perform(Operation::Cancel,true);return 0;}
    if(app->response.cameraActive)SetTimer(window,1,500,nullptr);return 0;
  }
  case WM_APP+3:{app->previewing=false;app->busy=false;{std::lock_guard lock(app->mutex);app->status=app->error.empty()?L"Preview closed. Webcam released.":app->error;}if(app->captureWindow)DestroyWindow(app->captureWindow);InvalidateRect(window,nullptr,FALSE);return 0;}
  case WM_APP+4:{std::vector<BYTE> packet;{std::lock_guard lock(app->mutex);packet=app->previewPacket;}if(app->previewing)app->show_capture(packet);return 0;}
  case WM_CLOSE:app->task.request_stop();if(app->task.joinable())app->task.join();if(app->response.cameraActive){try{Request r;r.operation=Operation::Cancel;call(r,app->demo);}catch(...){}}DestroyWindow(window);return 0;
  case WM_DESTROY:KillTimer(window,1);PostQuitMessage(0);return 0;
  }
  return DefWindowProcW(window,message,w,l);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,wchar_t* args,int) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  INITCOMMONCONTROLSEX common{sizeof(common),ICC_STANDARD_CLASSES};InitCommonControlsEx(&common);
  CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
  App app;app.instance=instance;app.demo=std::wstring(args).find(L"--demo")!=std::wstring::npos;
  WNDCLASSW wc{};wc.lpfnWndProc=window_proc;wc.hInstance=instance;wc.lpszClassName=L"FacePassSettings";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);RegisterClassW(&wc);
  app.dpi=GetDpiForSystem();
  app.font=CreateFontW(-app.s(15),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
  app.smallFont=CreateFontW(-app.s(13),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
  app.titleFont=CreateFontW(-app.s(29),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
  RECT size{0,0,app.s(970),app.s(735)};AdjustWindowRectExForDpi(&size,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,FALSE,0,app.dpi);
  HWND window=CreateWindowExW(0,wc.lpszClassName,L"FacePass Settings",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,size.right-size.left,size.bottom-size.top,nullptr,nullptr,instance,&app);
  if(!window)return 1;app.palette();app.render();ShowWindow(window,SW_SHOW);UpdateWindow(window);app.perform(Operation::Status);
  if(std::wstring(args).find(L"--selftest")!=std::wstring::npos) {
    // Test the app's own HWND/control construction, without enrollment, capture or installation.
    app.task.request_stop();if(app.task.joinable())app.task.join();
    bool valid=true;
    for(int page=0;page<4;++page){app.page=page;app.render();valid=valid&&GetDlgItem(window,NavOverview)&&GetDlgItem(window,NavAdvanced);if(page==1)valid=valid&&GetDlgItem(window,ModeControl)&&GetDlgItem(window,Apply)&&GetDlgItem(window,SavePassword)&&GetDlgItem(window,RemovePassword);if(page==2)valid=valid&&GetDlgItem(window,Enroll)&&GetDlgItem(window,CameraControl);}
    app.response.config.profile=Profile::Instant;app.page=2;app.render();
    valid=valid&&SendMessageW(GetDlgItem(window,ProfileControl),CB_GETCOUNT,0,0)==4&&SendMessageW(GetDlgItem(window,ProfileControl),CB_GETCURSEL,0,0)==static_cast<int>(Profile::Instant);
    app.dark=true;app.palette();app.page=2;app.render();app.dark=false;app.palette();app.page=0;app.render();UpdateWindow(window);
    // Capture only this newly created app window for layout review.
    RECT area{};GetClientRect(window,&area);HDC screen=GetDC(window),memory=CreateCompatibleDC(screen);
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=area.right;info.bmiHeader.biHeight=-area.bottom;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    void* pixels=nullptr;HBITMAP bitmap=CreateDIBSection(screen,&info,DIB_RGB_COLORS,&pixels,nullptr,0);auto old=SelectObject(memory,bitmap);
    if(bitmap&&pixels&&PrintWindow(window,memory,PW_CLIENTONLY)){
      std::filesystem::create_directories(L"test-output");cv::Mat image(area.bottom,area.right,CV_8UC4,pixels);cv::imwrite("test-output/settings-overview.png",image);
      app.page=2;app.render();UpdateWindow(window);if(PrintWindow(window,memory,PW_CLIENTONLY))cv::imwrite("test-output/settings-face.png",image);
      app.page=1;app.render();UpdateWindow(window);if(PrintWindow(window,memory,PW_CLIENTONLY))cv::imwrite("test-output/settings-authentication.png",image);
      app.page=2;app.render();
      app.dark=true;app.palette();app.render();UpdateWindow(window);if(PrintWindow(window,memory,PW_CLIENTONLY))cv::imwrite("test-output/settings-face-dark.png",image);
    }
    SelectObject(memory,old);if(bitmap)DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(window,screen);DestroyWindow(window);
    DeleteObject(app.font);DeleteObject(app.smallFont);DeleteObject(app.titleFont);DeleteObject(app.bg);DeleteObject(app.field);CoUninitialize();return valid?0:1;
  }
  MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
  DeleteObject(app.font);DeleteObject(app.smallFont);DeleteObject(app.titleFont);DeleteObject(app.bg);DeleteObject(app.field);CoUninitialize();return 0;
}
