#include "policymanager.h"

LSA_HANDLE PolicyManager::OpenPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES objectAttr;
	NTSTATUS status = 0x0;
	LSA_HANDLE policyHandle;

	LsaOpenPolicy_t myLsaOpenPolicy = (LsaOpenPolicy_t)GetProcAddress( moduleAdvApi_, "LsaOpenPolicy" );
	// Initializing objectattr to zeroes
	ZeroMemory(&objectAttr, sizeof(objectAttr));

	status = myLsaOpenPolicy( NULL, &objectAttr, 
		POLICY_ALL_ACCESS | POLICY_LOOKUP_NAMES, &policyHandle );
	
	/// 0xC0000022 - STATUS_ACCESS_DENIED
	/// it must be executed using powershell in sudo
	if ( status != 0 )
	{
		BOOST_LOG_TRIVIAL(error) << "Policy handle wasn't opened, error: 0x" 
			<< std::hex << status;
		return NULL;
	}
	return policyHandle;
}

LSA_HANDLE PolicyManager::GetPolicyHandle() const
{
	return policyHandle_;
}

void PolicyManager::DisplayUsersInfo() const
{
	std::cout << "Requested information \n" << UI_sep;

	NetUserEnum_t myNetUserEnum = (NetUserEnum_t)GetProcAddress(moduleNetApi_, "NetUserEnum");
	NetUserGetInfo_t myNetUserGetInfo = (NetUserGetInfo_t)GetProcAddress(moduleNetApi_, "NetUserGetInfo");
	ConvertSidToStringSidA_t myConvertSidToStringSidA = (ConvertSidToStringSidA_t)GetProcAddress(moduleAdvApi_, "ConvertSidToStringSidA");
	NetUserGetLocalGroups_t myNetUserGetLocalGroups = (NetUserGetLocalGroups_t)GetProcAddress(moduleNetApi_, "NetUserGetLocalGroups");
	LsaEnumerateAccountRights_t myLsaEnumerateAccountRights = (LsaEnumerateAccountRights_t)GetProcAddress(moduleAdvApi_, "LsaEnumerateAccountRights");

	LPUSER_INFO_3 infoBuffer = NULL;
	LPUSER_INFO_23 tempBuffer = NULL;
	DWORD entriesRead = 0;
	DWORD entriesTotal = 0;
	DWORD resumeHandle = 0;
	NET_API_STATUS status = NERR_Success;

	do
	{
		status = myNetUserEnum( NULL, 3, FILTER_NORMAL_ACCOUNT, (BYTE**)&infoBuffer, MAX_PREFERRED_LENGTH,
			&entriesRead, &entriesTotal, &resumeHandle );
		if ( status != NERR_Success )
		{
			BOOST_LOG_TRIVIAL(error) << "NetUserEnum error: 0x" << std::hex << status;
			break;
		}
		if ( infoBuffer != NULL )
		{
			for ( DWORD i = 0; i < entriesRead; ++i, ++infoBuffer )
			{
				// User name
				std::wcout << L"\tUser name: " << infoBuffer->usri3_name << std::endl;
				
				// User SID
				myNetUserGetInfo( NULL, infoBuffer->usri3_name, 23, (BYTE**)&tempBuffer );
				LPSTR sidString[256];
				myConvertSidToStringSidA( tempBuffer->usri23_user_sid, sidString );
				std::cout << "User SID: " << *sidString << std::endl;
				
				// User privilege level
				std::cout << "User's level of privilege: ";
				if ( infoBuffer->usri3_priv == USER_PRIV_GUEST )
					std::cout << "USER_PRIV_GUEST - Guest" << std::endl;
				if ( infoBuffer->usri3_priv == USER_PRIV_USER )
					std::cout << "USER_PRIV_USER - User" << std::endl;
				if ( infoBuffer->usri3_priv == USER_PRIV_ADMIN )
					std::cout << "USER_PRIV_ADMIN - Admin" << std::endl;
				
				// List of privileges
				PLSA_UNICODE_STRING privilegesBuffer;
				ULONG privilegesBufferSize = 0;
				status = myLsaEnumerateAccountRights( policyHandle_, tempBuffer->usri23_user_sid, &privilegesBuffer, 
					&privilegesBufferSize );
				std::cout << ( ( privilegesBufferSize == 0 ) ? 
					"User's rights from LSA: None" : "User's rights from LSA: " ) << std::endl;
				for ( ULONG j = 0; j < privilegesBufferSize; ++j )
				{
					std::wcout << privilegesBuffer[j].Buffer << std::endl;
				}
				
				// User's comment
				std::wcout << L"User's comment: " <<
					( (*infoBuffer->usri3_comment ) ? infoBuffer->usri3_comment : L"None") << std::endl;

				// User's local groups
				LPLOCALGROUP_USERS_INFO_0 groupsBuffer = NULL;
				DWORD groupsEntriesRead = 0;
				DWORD groupsEntriesTotal = 0;
				myNetUserGetLocalGroups( NULL, infoBuffer->usri3_name, 0, LG_INCLUDE_INDIRECT, 
					(BYTE**)&groupsBuffer, MAX_PREFERRED_LENGTH, &groupsEntriesRead, &groupsEntriesTotal );
				std::cout << ( ( groupsEntriesRead == 0 ) ?
					"User's local groups: None\n" : "User's local groups:" );
				for (DWORD j = 0; j < groupsEntriesRead; ++j, ++groupsBuffer, std::cout << ", ")
				{
					std::wcout << groupsBuffer->lgrui0_name;
				}
				std::cout << std::endl;
			}
		}
	} while ( status == ERROR_MORE_DATA );
	std::cout << UI_sep;
}