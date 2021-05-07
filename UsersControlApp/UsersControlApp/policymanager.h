///
/// @file PolicyManager
///

#include <Windows.h>
#include <LMaccess.h>
#include <Ntsecapi.h>
#include <iostream>
#include <LM.h>
#include <boost/log/trivial.hpp>

/// @brief Class PolicyManager for controlling users and groups in Windows
///
class PolicyManager
{
public:
     // Constructor
     //
     PolicyManager()
     {
          // Dynamic libraries loading
          moduleAdvApi_ = LoadLibrary( "Advapi32.dll" );
          moduleNetApi_ = LoadLibrary( "Netapi32.dll" );
          policyHandle_ = OpenPolicyHandle();
     }
          
     // Destructor
     //
     ~PolicyManager()
     {
          // Freeing libraries 
          FreeLibrary( moduleAdvApi_ );
          FreeLibrary( moduleNetApi_ );
          LsaClose( policyHandle_ );
     };

     /// @brief Function for opening LSA policy handle
     /// @return Handle to policy object
     /// 	    
     LSA_HANDLE OpenPolicyHandle();

     /// @brief Get function for policyHandle
     /// @return Policy handle
     LSA_HANDLE GetPolicyHandle() const;

private:
     LSA_HANDLE policyHandle_; ///< Handle to policy object on local PC
     HMODULE moduleAdvApi_;    ///< Handle to Advapi32.dll
     HMODULE moduleNetApi_;    ///< Handle to Netapi32.dll
     
};

// Dynamic library prototypes
namespace 
{
     typedef NTSTATUS(__stdcall* LsaOpenPolicy_t)(
          PLSA_UNICODE_STRING SystemName,
          PLSA_OBJECT_ATTRIBUTES ObjectAtributes,
          ACCESS_MASK DesiredAccess,
          PLSA_HANDLE PolicyHandle
          );
     typedef NET_API_STATUS(__stdcall* NetUserAdd_t)(
          LPCWSTR servername,
          DWORD   level,
          LPBYTE  buf,
          LPDWORD parm_err
          );
     typedef NET_API_STATUS(__stdcall* NetUserEnum_t)(
          LPCWSTR servername,
          DWORD   level,
          DWORD   filter,
          LPBYTE* bufptr,
          DWORD   prefmaxlen,
          LPDWORD entriesread,
          LPDWORD totalentries,
          PDWORD  resume_handle
          );
     typedef NET_API_STATUS(__stdcall* NetUserGetInfo_t)(
          LPCWSTR servername,
          LPCWSTR username,
          DWORD   level,
          LPBYTE* bufptr
          );
     typedef NET_API_STATUS(__stdcall* NetUserDel_t)(
          LPCWSTR servername,
          LPCWSTR username
          );
     typedef NET_API_STATUS(__stdcall* NetUserGetLocalGroups_t)(
          LPCWSTR servername,
          LPCWSTR username,
          DWORD   level,
          DWORD   flags,
          LPBYTE* bufptr,
          DWORD   prefmaxlen,
          LPDWORD entriesread,
          LPDWORD totalentries
          );
     typedef NET_API_STATUS(__stdcall* NetGroupEnum_t)(
          LPCWSTR    servername,
          DWORD      level,
          LPBYTE* bufptr,
          DWORD      prefmaxlen,
          LPDWORD    entriesread,
          LPDWORD    totalentries,
          PDWORD_PTR resume_handle
          );
     typedef NET_API_STATUS(__stdcall* NetGroupGetInfo_t)(
          LPCWSTR servername,
          LPCWSTR groupname,
          DWORD   level,
          LPBYTE* bufptr
          );
     typedef NET_API_STATUS(__stdcall* NetLocalGroupAdd_t)(
          LPCWSTR servername,
          DWORD   level,
          LPBYTE  buf,
          LPDWORD parm_err
          );
     typedef NET_API_STATUS(__stdcall* NetLocalGroupEnum_t)(
          LPCWSTR    servername,
          DWORD      level,
          LPBYTE* bufptr,
          DWORD      prefmaxlen,
          LPDWORD    entriesread,
          LPDWORD    totalentries,
          PDWORD_PTR resumehandle
          );
     typedef NET_API_STATUS(__stdcall* NetLocalGroupDel_t)(
          LPCWSTR servername,
          LPCWSTR groupname
          );
     typedef BOOL(__stdcall* ConvertSidToStringSidA_t)(
          PSID  Sid,
          LPSTR* StringSid
          );
     typedef NTSTATUS(__stdcall* LsaEnumerateAccountRights_t)(
          LSA_HANDLE          PolicyHandle,
          PSID                AccountSid,
          PLSA_UNICODE_STRING* UserRights,
          PULONG              CountOfRights
          );
     typedef BOOL(__stdcall* LookupAccountNameW_t)(
          LPCWSTR       lpSystemName,
          LPCWSTR       lpAccountName,
          PSID          Sid,
          LPDWORD       cbSid,
          LPWSTR        ReferencedDomainName,
          LPDWORD       cchReferencedDomainName,
          PSID_NAME_USE peUse
          );
     typedef NTSTATUS(__stdcall* LsaAddAccountRights_t)(
          LSA_HANDLE          PolicyHandle,
          PSID                AccountSid,
          PLSA_UNICODE_STRING UserRights,
          ULONG               CountOfRights
          );
     typedef NTSTATUS(__stdcall* LsaRemoveAccountRights_t)(
          LSA_HANDLE          PolicyHandle,
          PSID                AccountSid,
          BOOLEAN             AllRights,
          PLSA_UNICODE_STRING UserRights,
          ULONG               CountOfRights
          );
     typedef BOOL(__stdcall* LookupAccountNameA_t)(
          LPCSTR        lpSystemName,
          LPCSTR        lpAccountName,
          PSID          Sid,
          LPDWORD       cbSid,
          LPSTR         ReferencedDomainName,
          LPDWORD       cchReferencedDomainName,
          PSID_NAME_USE peUse
          );
} ///< end of namespace