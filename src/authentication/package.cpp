#define SECURITY_WIN32
#include "facepass/ipc.hpp"
#include <ntsecapi.h>
#include <security.h>
#include <ntsecpkg.h>
#include <wtsapi32.h>
#include <lm.h>
#include <cstring>
#include <limits>

using namespace facepass;
namespace {
constexpr NTSTATUS Success=0;
constexpr NTSTATUS Denied=static_cast<NTSTATUS>(0xc000006d);
constexpr NTSTATUS Invalid=static_cast<NTSTATUS>(0xc000000d);
constexpr NTSTATUS NoMemory=static_cast<NTSTATUS>(0xc0000017);
constexpr NTSTATUS NotSupported=static_cast<NTSTATUS>(0xc00000bb);
LSA_DISPATCH_TABLE dispatch{};
bool initialized=false;

PUNICODE_STRING text(const std::wstring& value) {
  const auto bytes=(value.size()+1)*sizeof(wchar_t);
  if(bytes>USHRT_MAX) throw std::runtime_error("Audit name too long");
  auto p=static_cast<PUNICODE_STRING>(dispatch.AllocateLsaHeap(static_cast<ULONG>(sizeof(UNICODE_STRING)+bytes)));
  if(!p) throw std::bad_alloc();
  p->Buffer=reinterpret_cast<wchar_t*>(p+1); p->Length=static_cast<USHORT>(bytes-sizeof(wchar_t)); p->MaximumLength=static_cast<USHORT>(bytes);
  std::memcpy(p->Buffer,value.c_str(),bytes); return p;
}
bool locked_console(DWORD session) {
  if(session!=WTSGetActiveConsoleSessionId()) return false;
  wchar_t* raw=nullptr; DWORD bytes=0;
  if(!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,session,WTSSessionInfoEx,&raw,&bytes)) return false;
  bool locked=bytes>=sizeof(WTSINFOEXW) && reinterpret_cast<WTSINFOEXW*>(raw)->Level==1
      && reinterpret_cast<WTSINFOEXW*>(raw)->Data.WTSInfoExLevel1.SessionFlags==WTS_SESSIONSTATE_LOCK;
  WTSFreeMemory(raw); return locked;
}
std::vector<BYTE> token_info(HANDLE token,TOKEN_INFORMATION_CLASS type) {
  DWORD size=0; GetTokenInformation(token,type,nullptr,0,&size);
  if(!size || size>1024*1024) throw std::runtime_error("Invalid native token data");
  std::vector<BYTE> bytes(size);
  if(!GetTokenInformation(token,type,bytes.data(),size,&size)) fail("Query native session token");
  return bytes;
}
// V2 is a single LSA allocation. Every embedded pointer stays inside it.
PVOID clone_native_token(HANDLE token) {
  auto user=token_info(token,TokenUser), groups=token_info(token,TokenGroups), privileges=token_info(token,TokenPrivileges);
  auto owner=token_info(token,TokenOwner), primary=token_info(token,TokenPrimaryGroup), dacl=token_info(token,TokenDefaultDacl), stats=token_info(token,TokenStatistics);
  auto g=reinterpret_cast<TOKEN_GROUPS*>(groups.data());
  auto u=reinterpret_cast<TOKEN_USER*>(user.data());
  auto o=reinterpret_cast<TOKEN_OWNER*>(owner.data());
  auto p=reinterpret_cast<TOKEN_PRIMARY_GROUP*>(primary.data());
  auto a=reinterpret_cast<TOKEN_DEFAULT_DACL*>(dacl.data())->DefaultDacl;
  std::vector<SID_AND_ATTRIBUTES> selected;
  for(DWORD i=0;i<g->GroupCount;++i) {
    const auto& group=g->Groups[i];
    if((group.Attributes&SE_GROUP_LOGON_ID)==SE_GROUP_LOGON_ID || IsWellKnownSid(group.Sid,WinWorldSid) || IsWellKnownSid(group.Sid,WinLocalSid)) continue;
    selected.push_back(group);
  }
  auto align=[](size_t n){return (n+7)&~size_t(7);};
  size_t size=align(sizeof(LSA_TOKEN_INFORMATION_V2));
  size+=align(GetLengthSid(u->User.Sid))+align(GetLengthSid(o->Owner))+align(GetLengthSid(p->PrimaryGroup));
  size+=align(FIELD_OFFSET(TOKEN_GROUPS,Groups)+selected.size()*sizeof(SID_AND_ATTRIBUTES));
  size+=align(privileges.size())+align(a?a->AclSize:0);
  for(const auto& group:selected) size+=align(GetLengthSid(group.Sid));
  if(size>1024*1024) throw std::runtime_error("Native token exceeds package limit");
  auto block=static_cast<BYTE*>(dispatch.AllocateLsaHeap(static_cast<ULONG>(size)));
  if(!block) throw std::bad_alloc();
  std::memset(block,0,size); size_t offset=align(sizeof(LSA_TOKEN_INFORMATION_V2));
  auto copy=[&](const void* source,size_t count)->void* { auto dest=block+offset; std::memcpy(dest,source,count); offset+=align(count); return dest; };
  auto result=reinterpret_cast<LSA_TOKEN_INFORMATION_V2*>(block);
  result->ExpirationTime=reinterpret_cast<TOKEN_STATISTICS*>(stats.data())->ExpirationTime;
  result->User={copy(u->User.Sid,GetLengthSid(u->User.Sid)),u->User.Attributes};
  result->Owner.Owner=copy(o->Owner,GetLengthSid(o->Owner));
  result->PrimaryGroup.PrimaryGroup=copy(p->PrimaryGroup,GetLengthSid(p->PrimaryGroup));
  result->Groups=reinterpret_cast<TOKEN_GROUPS*>(block+offset);
  offset+=align(FIELD_OFFSET(TOKEN_GROUPS,Groups)+selected.size()*sizeof(SID_AND_ATTRIBUTES));
  result->Groups->GroupCount=static_cast<DWORD>(selected.size());
  for(size_t i=0;i<selected.size();++i) result->Groups->Groups[i]={copy(selected[i].Sid,GetLengthSid(selected[i].Sid)),selected[i].Attributes};
  result->Privileges=static_cast<TOKEN_PRIVILEGES*>(copy(privileges.data(),privileges.size()));
  result->DefaultDacl.DefaultDacl=a?static_cast<PACL>(copy(a,a->AclSize)):nullptr;
  return result;
}
bool local_account(HANDLE token,std::wstring& name,std::wstring& domain) {
  auto user=token_info(token,TokenUser); auto sid=reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
  wchar_t account[256]{},authority[256]{},computer[256]{}; DWORD accountSize=std::size(account),authoritySize=std::size(authority),computerSize=std::size(computer); SID_NAME_USE use{};
  if(!LookupAccountSidW(nullptr,sid,account,&accountSize,authority,&authoritySize,&use) || use!=SidTypeUser
      || !GetComputerNameW(computer,&computerSize) || _wcsicmp(authority,computer)!=0) return false;
  USER_INFO_4* info=nullptr;
  if(NetUserGetInfo(nullptr,account,4,reinterpret_cast<BYTE**>(&info))!=NERR_Success) return false;
  bool allowed=info && EqualSid(sid,info->usri4_user_sid) && !(info->usri4_flags&(UF_ACCOUNTDISABLE|UF_LOCKOUT))
      && (info->usri4_acct_expires==TIMEQ_FOREVER || info->usri4_acct_expires>unix_millis()/1000);
  NetApiBufferFree(info); if(!allowed) return false;
  name=account; domain=authority; return true;
}
}

extern "C" NTSTATUS NTAPI LsaApInitializePackage(ULONG,PLSA_DISPATCH_TABLE table,PLSA_STRING,PLSA_STRING,PLSA_STRING* name) {
  if(!table || !name || !table->AllocateLsaHeap || !table->FreeLsaHeap || !table->CreateLogonSession || !table->DeleteLogonSession) return Invalid;
  *name=nullptr; dispatch=*table;
  auto p=static_cast<PLSA_STRING>(dispatch.AllocateLsaHeap(sizeof(LSA_STRING)+sizeof(UnlockPackageName)));
  if(!p) return NoMemory;
  p->Buffer=reinterpret_cast<char*>(p+1); p->Length=sizeof(UnlockPackageName)-1; p->MaximumLength=sizeof(UnlockPackageName);
  std::memcpy(p->Buffer,UnlockPackageName,sizeof(UnlockPackageName)); *name=p; initialized=true; return Success;
}
extern "C" NTSTATUS LsaApLogonUserEx2(PLSA_CLIENT_REQUEST request,SECURITY_LOGON_TYPE type,PVOID buffer,PVOID,ULONG bytes,
    PVOID* profile,PULONG profileBytes,PLUID logon,PNTSTATUS sub,PLSA_TOKEN_INFORMATION_TYPE tokenType,PVOID* token,
    PUNICODE_STRING* account,PUNICODE_STRING* authority,PUNICODE_STRING* machine,PSECPKG_PRIMARY_CRED primary,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* supplemental) {
  if(!profile || !profileBytes || !logon || !sub || !tokenType || !token || !account || !primary || !supplemental) return Invalid;
  *profile=nullptr; *profileBytes=0; *logon={}; *sub=Denied; *tokenType=LsaTokenInformationNull; *token=nullptr; *account=nullptr;
  if(authority)*authority=nullptr; if(machine)*machine=nullptr; *primary={}; *supplemental=nullptr;
  if(!initialized) return Denied;
  PVOID allocatedToken=nullptr; bool created=false;
  try {
    *account=text(L"FacePass unlock");
    // Interactive is used for workstation unlock by newer Windows LogonUI.
    // Both forms require an existing locked console session: boot logon is refused.
    if((type!=Unlock && type!=Interactive) || !request || !buffer || bytes!=sizeof(UnlockLogon) || !passwordless_enabled()) return Denied;
    UnlockLogon input{}; std::memcpy(&input,buffer,sizeof(input));
    if(input.magic!=ProtocolMagic || input.version!=1 || !valid_ticket(input.ticket,unix_millis()) || !locked_console(input.ticket.session)) return Denied;
    HANDLE raw=nullptr; if(!WTSQueryUserToken(input.ticket.session,&raw)) return Denied;
    Handle native(raw); std::wstring name,domain;
    if(token_sid(native.get())!=input.ticket.sid || !local_account(native.get(),name,domain)) return Denied;
    dispatch.FreeLsaHeap(*account); *account=nullptr; *account=text(name);
    if(authority)*authority=text(domain); if(machine)*machine=text(domain);
    allocatedToken=clone_native_token(native.get());
    Request consume; consume.operation=Operation::ConsumeUnlock; consume.ticket=input.ticket; wcscpy_s(consume.targetSid,input.ticket.sid);
    call(consume); // SCM-verified service; only real LSASS can consume a one-use grant.
    if(!locked_console(input.ticket.session)) throw std::runtime_error("Session changed during authorization");
    if(!AllocateLocallyUniqueId(logon)) throw std::runtime_error("Cannot allocate authentication session");
    if(dispatch.CreateLogonSession(logon)<0) throw std::runtime_error("Cannot create authentication session");
    created=true;
    MSV1_0_INTERACTIVE_PROFILE nativeProfile{}; nativeProfile.MessageType=MsV1_0InteractiveProfile;
    nativeProfile.LogoffTime.QuadPart=std::numeric_limits<LONGLONG>::max(); nativeProfile.KickOffTime=nativeProfile.LogoffTime;
    if(dispatch.AllocateClientBuffer(request,sizeof(nativeProfile),profile)<0
        || dispatch.CopyToClientBuffer(request,sizeof(nativeProfile),*profile,&nativeProfile)<0) throw std::runtime_error("Cannot return unlock profile");
    *profileBytes=sizeof(nativeProfile); *tokenType=LsaTokenInformationV2; *token=allocatedToken; allocatedToken=nullptr;
    *sub=Success; return Success;
  } catch(...) {
    if(allocatedToken) dispatch.FreeLsaHeap(allocatedToken);
    if(*profile && dispatch.FreeClientBuffer) dispatch.FreeClientBuffer(request,*profile);
    *profile=nullptr; *profileBytes=0;
    if(created) dispatch.DeleteLogonSession(logon); *logon={};
    return Denied;
  }
}
extern "C" NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST,PVOID,PVOID,ULONG,PVOID* output,PULONG bytes,PNTSTATUS status) {
  if(output)*output=nullptr; if(bytes)*bytes=0; if(status)*status=NotSupported; return NotSupported;
}
extern "C" NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST r,PVOID b,PVOID c,ULONG n,PVOID* o,PULONG s,PNTSTATUS t) { return LsaApCallPackage(r,b,c,n,o,s,t); }
extern "C" NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST r,PVOID b,PVOID c,ULONG n,PVOID* o,PULONG s,PNTSTATUS t) { return LsaApCallPackage(r,b,c,n,o,s,t); }
extern "C" void NTAPI LsaApLogonTerminated(PLUID) {}
#ifdef FACEPASS_AUTH_TESTING
PVOID facepass_test_clone_native_token(HANDLE token) { return clone_native_token(token); }
#endif
