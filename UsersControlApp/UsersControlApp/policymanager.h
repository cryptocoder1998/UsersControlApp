///
/// @file PolicyManager
///

#include <Windows.h>
#include <LMaccess.h>
#include <Ntsecapi.h>
#include <iostream>
#include <LM.h>
#include <boost/log/trivial.hpp>
#include <string>
#include <sddl.h>

// UI things
namespace 
{
     const std::string UI_sep = "/------------------------------------------------------/\n";
     // User menu
     const std::string UI =
          "Enter one of possible commands:\n"
          "/------------------------------------------------------/\n"
          "1 - Display information about system users\n"
          "2 - Display information about local system groups\n"
          "3 - Display information about global system groups\n"
          "4 - Create a user\n"
          "5 - Create a group\n"
          "6 - Delete a user\n"
          "7 - Delete a group\n"
          "8 - Add user privilege\n"
          "9 - Add group privilege\n"
          "10 - Remove user privilege\n"
          "11 - Remove group privilege\n"
          "/------------------------------------------------------/\n";

     // Enum for user's choice
     enum userChoices {
          DISPLAY_SYSTEM_USERS = 1,
          DISPLAY_LOCAL_GROUPS,
          DISPLAY_GLOBAL_GROUPS,
          CREATE_USER,
          CREATE_GROUP,
          DELETE_USER,
          DELETE_GROUP,
          ADD_USER_PRIVELEGE,
          ADD_GROUP_PRIVELEGE,
          DELETE_USER_PRIVELEGE,
          DELETE_GROUP_PRIVELEGE
     };
}


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
     /// 
     LSA_HANDLE GetPolicyHandle() const;

     /// @brief Method for showing information about system users
     ///
     void DisplayUsersInfo() const;

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