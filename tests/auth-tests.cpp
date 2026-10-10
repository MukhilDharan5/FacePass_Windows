#define SECURITY_WIN32
#include "facepass/unlock.hpp"
#include <ntsecapi.h>
#include <security.h>
#include <ntsecpkg.h>
#include <iostream>
#include <set>

extern "C" NTSTATUS NTAPI LsaApInitializePackage(ULONG,PLSA_DISPATCH_TABLE,PLSA_STRING,PLSA_STRING,PLSA_STRING*);
extern "C" NTSTATUS LsaApLogonUserEx2(PLSA_CLIENT_REQUEST,SECURITY_LOGON_TYPE,PVOID,PVOID,ULONG,PVOID*,PULONG,PLUID,PNTSTATUS,PLSA_TOKEN_INFORMATION_TYPE,PVOID*,PUNICODE_STRING*,PUNICODE_STRING*,PUNICODE_STRING*,PSECPKG_PRIMARY_CRED,PSECPKG_SUPPLEMENTAL_CRED_ARRAY*);
extern "C" NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST,PVOID,PVOID,ULONG,PVOID*,PULONG,PNTSTATUS);
PVOID facepass_test_clone_native_token(HANDLE);
namespace {
int checks=0; std::set<void*> allocations;
void check(bool value,const char* label){++checks;if(!value)throw std::runtime_error(label);}
PVOID NTAPI allocate(ULONG bytes){auto p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes);if(p)allocations.insert(p);return p;}
void NTAPI release(PVOID p){if(p){check(allocations.erase(p)==1,"free only LSA-owned memory");HeapFree(GetProcessHeap(),0,p);}}
NTSTATUS NTAPI create(PLUID){throw std::runtime_error("rejected logon must never create a session");}
NTSTATUS NTAPI remove(PLUID){return 0;}
}
int wmain(int argc,wchar_t** argv){
  try {
    check(argc==2,"authentication DLL supplied to contract test");auto module=LoadLibraryW(argv[1]);check(module!=nullptr,"authentication DLL loads without registration");
    for(auto symbol:{"LsaApInitializePackage","LsaApLogonUserEx2","LsaApCallPackage","LsaApCallPackageUntrusted","LsaApCallPackagePassthrough","LsaApLogonTerminated"})check(GetProcAddress(module,symbol)!=nullptr,"required LSA entry point exported");
    FreeLibrary(module);
    LSA_DISPATCH_TABLE table{};table.AllocateLsaHeap=allocate;table.FreeLsaHeap=release;table.CreateLogonSession=create;table.DeleteLogonSession=remove;
    PLSA_STRING name=nullptr;check(LsaApInitializePackage(0,&table,nullptr,nullptr,&name)==0,"package initializes with LSA allocator");
    check(std::string(name->Buffer,name->Length)==facepass::UnlockPackageName,"registered authentication package name");release(name);
    for(auto type:{Network,Batch,Service,RemoteInteractive,Unlock,Interactive}) {
      void* profile=reinterpret_cast<void*>(1);ULONG bytes=1;LUID logon{};NTSTATUS sub=0;LSA_TOKEN_INFORMATION_TYPE tokenType{};void* token=reinterpret_cast<void*>(1);
      PUNICODE_STRING account=nullptr,authority=nullptr,machine=nullptr;SECPKG_PRIMARY_CRED primary{};PSECPKG_SUPPLEMENTAL_CRED_ARRAY supplemental=nullptr;
      auto status=LsaApLogonUserEx2(nullptr,type,nullptr,nullptr,0,&profile,&bytes,&logon,&sub,&tokenType,&token,&account,&authority,&machine,&primary,&supplemental);
      check(status<0 && sub<0,"unauthorized and malformed logon rejected");check(!profile&&!bytes&&!token&&!primary.Password.Buffer&&!supplemental,"rejection leaves no token or secret");
      check(account!=nullptr,"failed authentication has audit account");release(account);release(authority);release(machine);
    }
    void* output=reinterpret_cast<void*>(1);ULONG size=1;NTSTATUS result=0;
    check(LsaApCallPackageUntrusted(nullptr,nullptr,nullptr,0,&output,&size,&result)<0&&!output&&!size,"untrusted package calls denied");
    HANDLE raw=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)!=FALSE,"query native test token");facepass::Handle native(raw);
    auto clone=static_cast<LSA_TOKEN_INFORMATION_V2*>(facepass_test_clone_native_token(native.get()));
    check(clone && IsValidSid(clone->User.User.Sid) && IsValidSid(clone->PrimaryGroup.PrimaryGroup),"native identity copied into V2 token information");
    check(clone->Groups&&clone->Privileges,"native groups and privileges copied");
    const auto blockSize=HeapSize(GetProcessHeap(),0,clone);const auto base=reinterpret_cast<uintptr_t>(clone);
    auto inside=[&](const void* p){auto value=reinterpret_cast<uintptr_t>(p);return value>=base&&value<base+blockSize;};
    check(inside(clone->User.User.Sid)&&inside(clone->Groups)&&inside(clone->PrimaryGroup.PrimaryGroup)&&inside(clone->Owner.Owner)&&inside(clone->Privileges),"V2 token pointers belong to one LSA-owned allocation");
    for(DWORD i=0;i<clone->Groups->GroupCount;++i)check(inside(clone->Groups->Groups[i].Sid)&&IsValidSid(clone->Groups->Groups[i].Sid),"copied group SIDs remain valid after native-query buffers are freed");
    bool oldLogon=false;for(DWORD i=0;i<clone->Groups->GroupCount;++i)oldLogon|=(clone->Groups->Groups[i].Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID;
    check(!oldLogon,"old session logon SID excluded from new authentication token");
    release(clone);check(allocations.empty(),"all mocked LSA allocations released");
    std::cout<<"PASS: "<<checks<<" authentication checks (no LSA registration)\n";return 0;
  }catch(const std::exception& ex){std::cerr<<"FAILED: "<<ex.what()<<'\n';return 1;}
}
